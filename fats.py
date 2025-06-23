#!/usr/bin/env python

"""
 _______  _______ _________ _______
(  ____ \(  ___  )\__   __/(  ____ \
| (    \/| (   ) |   ) (   | (    \/
| (__    | (___) |   | |   | (_____
|  __)   |  ___  |   | |   (_____  )
| (      | (   ) |   | |         ) |
| )      | )   ( |   | |   /\____) |
|/       |/     \|   )_(   \_______)

#FUZZ ALL THE fileSystem

FATS: A FUSE-based passthrough filesystem that fuzzes files on access.

This script uses FUSE (Filesystem in Userspace) to mirror a directory,
but intercepts file 'open' calls. When a file is opened, it is first
mutated by the 'radamsa' fuzzer, and the application receives the fuzzed
version. This is useful for testing application resilience against
corrupted or unexpected file inputs.
"""

from __future__ import with_statement

import os
import sys
import errno
import subprocess
import tempfile
import re

# FUSE library for Python. Install with 'pip install fusepy'.
from fuse import FUSE, FuseOSError, Operations


class FATS(Operations):
    """
    A FUSE passthrough filesystem that intercepts file reads to provide
    fuzzed data.

    All filesystem operations are passed to the underlying OS, except for 'open'.
    When a file is opened, we create a temporary fuzzed version and return a
    file handle to it. The temporary file is cleaned up on 'release' (close).
    """

    def __init__(self, root):
        """
        Initialize the filesystem.

        Args:
            root (str): The path to the directory to be mirrored.
        """
        self.root = root
        # This dictionary maps file handles (fh) to the paths of our
        # temporary fuzzed files. This is crucial for cleanup.
        self.temp_files = {}

    # Helpers
    # =======

    def _full_path(self, partial):
        """
        Calculate the absolute path of a file in the underlying filesystem.

        Args:
            partial (str): The path requested by the FUSE system, relative to
                           the mountpoint.

        Returns:
            str: The full, absolute path in the real filesystem.
        """
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    # Filesystem methods
    # ==================

    def access(self, path, mode):
        """Check if a file can be accessed."""
        full_path = self._full_path(path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def chmod(self, path, mode):
        """Change the mode (permissions) of a file."""
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        """Change the owner and group of a file."""
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        """
        Return file attributes.

        The 'st_dev' and 'st_blksize' attributes are ignored.
        """
        full_path = self._full_path(path)
        st = os.lstat(full_path)
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                                                        'st_gid', 'st_mode', 'st_mtime',
                                                        'st_nlink', 'st_size', 'st_uid'))

    def readdir(self, path, fh):
        """Read a directory."""
        full_path = self._full_path(path)

        # The first two entries must be '.' and '..'.
        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for r in dirents:
            yield r

    def readlink(self, path):
        """Read a symbolic link."""
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    def mknod(self, path, mode, dev):
        """Create a special or ordinary file."""
        return os.mknod(self._full_path(path), mode, dev)

    def rmdir(self, path):
        """Remove a directory."""
        full_path = self._full_path(path)
        return os.rmdir(full_path)

    def mkdir(self, path, mode):
        """Create a directory."""
        return os.mkdir(self._full_path(path), mode)

    def statfs(self, path):
        """Return filesystem statistics."""
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
                                                         'f_blocks', 'f_bsize', 'f_favail',
                                                         'f_ffree', 'f_files', 'f_flag',
                                                         'f_frsize', 'f_namemax'))

    def unlink(self, path):
        """Remove (delete) a file."""
        return os.unlink(self._full_path(path))

    def symlink(self, name, target):
        """Create a symbolic link."""
        return os.symlink(name, self._full_path(target))

    def rename(self, old, new):
        """Rename a file."""
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        """Create a hard link to a file."""
        return os.link(self._full_path(target), self._full_path(name))

    def utimens(self, path, times=None):
        """Set access and modification times of a file."""
        return os.utime(self._full_path(path), times)

    # File methods
    # ============
    # These methods operate on file handles (fh) returned by open() or create().

    def open(self, path, flags):
        """
        Open a file - THIS IS THE FUZZING CORE.

        When a file is opened, instead of returning a handle to the original,
        this method creates a temporary fuzzed version of the file and returns
        a handle to that instead.
        """
        full_path = self._full_path(path)
        print(f"--- Fuzzing {path} ---")

        # Create a temporary file to hold the fuzzed output.
        # We use delete=False because the file needs to stay open until release().
        try:
            temp_fuzzed_file = tempfile.NamedTemporaryFile(delete=False)
            temp_fuzzed_path = temp_fuzzed_file.name
            temp_fuzzed_file.close()  # Close the handle from NamedTemporaryFile
        except Exception as e:
            print(f"Error: Could not create temporary file: {e}")
            raise FuseOSError(errno.EIO)  # Input/output error

        # Build and run the radamsa command using subprocess for security.
        command = ["radamsa", full_path]
        try:
            with open(temp_fuzzed_path, "wb") as f_out:
                result = subprocess.run(command, stdout=f_out, check=True)
        except FileNotFoundError:
            print("Error: 'radamsa' command not found.")
            print("Please install radamsa and ensure it is in your system's PATH.")
            os.remove(temp_fuzzed_path)  # Clean up
            raise FuseOSError(errno.EIO)
        except subprocess.CalledProcessError as e:
            print(f"Error: Radamsa failed to fuzz the file: {e}")
            os.remove(temp_fuzzed_path)  # Clean up
            raise FuseOSError(errno.EIO)
        except Exception as e:
            print(f"An unexpected error occurred during fuzzing: {e}")
            os.remove(temp_fuzzed_path)  # Clean up
            raise FuseOSError(errno.EIO)

        # Open the newly created fuzzed file and get a file handle.
        fh = os.open(temp_fuzzed_path, flags)

        # Store the path of the temporary file so we can delete it on release().
        self.temp_files[fh] = temp_fuzzed_path
        print(f"--- Fuzzing complete. Serving from {temp_fuzzed_path} ---")

        return fh

    def create(self, path, mode, fi=None):
        """Create and open a new file."""
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        """Read data from an open file."""
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    def write(self, path, buf, offset, fh):
        """Write data to an open file."""
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        """Truncate a file to a specified length."""
        # If fh is None, this is a path-based truncate. Otherwise, it's handle-based.
        if fh is not None:
            # This would be complex with our temp file model, so we pass for now.
            # A full implementation would need to handle this on the temp file.
            pass
        else:
            full_path = self._full_path(path)
            with open(full_path, 'r+') as f:
                f.truncate(length)

    def flush(self, path, fh):
        """Flush pending data to disk."""
        return os.fsync(fh)

    def release(self, path, fh):
        """
        Release an open file.

        This is the counterpart to open(). It's called when the last file
        handle is closed. This is our chance to clean up the temporary fuzzed file.
        """
        temp_path = self.temp_files.pop(fh, None)
        if temp_path:
            try:
                os.remove(temp_path)
                print(f"--- Cleaned up temp file {temp_path} ---")
            except OSError as e:
                print(f"Error cleaning up temp file {temp_path}: {e}")

        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        """Synchronize file's in-core state with storage device."""
        return self.flush(path, fh)


def main(root, mountpoint):
    """
    Mount the filesystem.
    """
    print("Mounting FATS...")
    print(f"  Source: {os.path.abspath(root)}")
    print(f"  Mount Point: {os.path.abspath(mountpoint)}")
    print("Press Ctrl+C to unmount.")

    FUSE(FATS(root), mountpoint, nothreads=True, foreground=True)

    print("FATS unmounted.")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <root_directory> <mount_point>")
        sys.exit(1)

    root_dir = sys.argv[1]
    mount_point = sys.argv[2]

    if not os.path.isdir(root_dir):
        print(f"Error: Root directory '{root_dir}' does not exist.")
        sys.exit(1)

    if not os.path.isdir(mount_point):
        print(f"Error: Mount point '{mount_point}' does not exist.")
        sys.exit(1)

    main(root_dir, mount_point)