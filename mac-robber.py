#!/usr/bin/env python3
#
# Author:  Jim Clausing
# Date:    2022-01-28
# Version: 1.5
#
# Updated by Miguel Quero with pystatx code to support btime
#
# Desc: rewrite of the sleithkit mac-robber in Python
# Unlinke the TSK version, this one can actually includes the MD5 & inode number
# though I still return a 0 in the MD5 column for non-regular files, but calculating
# hashes likely will modify atime, so it is turned off by default
#
# Note: in Python 2.7.x, st_ino, st_dev, st_nlink, st_uid, and st_gid are dummy variables
# on Windows systems. This is apparently fixed in current Python 3 versions.
# On *ALL* systems, os.stat does not return btime, so we put 0 there. :-(
#
# A useful way to use this on a live Linux system is with read-only --bind mounts
#
#   # mount --bind / /mnt
#   # mount -o ro,remount,bind /mnt
#   # ./mac-robber.py -5 -x /mnt/tmp -r /mnt -m system-foo:/ /mnt
#
# This gets us hashes, but because the bind mount is read-only doesn't update atimes
#
# Copyright (c) 2017-2022 AT&T Open Source. All rights reserved.
#

from __future__ import print_function
import os
import sys
import argparse
import hashlib
import platform
import ctypes
import functools

import subprocess

from stat import *

__version_info__ = (1, 5, 0)
__version__ = ".".join(map(str, __version_info__))

def _get_syscall_number():
    if platform.system() != 'Linux':
        return None
    machine = platform.machine()
    if machine == 'x86_64':
        return 332
    elif machine.startswith('arm') or machine.startswith('aarch'):
        return 291
    elif machine == 'i386' or machine == 'i686':
        return 383
    elif machine == 'ppc64le':
        return 383
    return None


def _get_syscall_func():
    syscall_nr = _get_syscall_number()
    if syscall_nr is None:
        raise RuntimeError(
            'Only x86, arm64, x86_64 and ppc64le machines on Linux are supported.')
    syscall = ctypes.CDLL(None).syscall
    syscall.restype = ctypes.c_int
    syscall.argtypes = [
        ctypes.c_long, ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(_StructStatx)
    ]
    return functools.partial(syscall, syscall_nr)


class _StructStatxTimestamp(ctypes.Structure):
    """statx file timestamp C struct."""

    _fields_ = [
        ('tv_sec', ctypes.c_longlong),  # Seconds since the Epoch (UNIX time)
        ('tv_nsec', ctypes.c_uint),  # Nanoseconds since tv_sec
        ('__statx_timestamp_pad1', ctypes.c_int * 1)
    ]


class _StructStatx(ctypes.Structure):
    """statx data buffer C struct."""

    _fields_ = [
        ('stx_mask', ctypes.c_uint),  # Mask of bits indicating filled fields
        ('stx_blksize', ctypes.c_uint),  # Block size for filesystem I/O
        ('stx_attributes',
         ctypes.c_ulonglong),  # Extra file attribute indicators
        ('stx_nlink', ctypes.c_uint),  # Number of hard links
        ('stx_uid', ctypes.c_uint),  # User ID of owner
        ('stx_gid', ctypes.c_uint),  # Group ID of owner
        ('stx_mode', ctypes.c_ushort),  # File type and mode
        ('__statx_pad1', ctypes.c_ushort * 1),
        ('stx_ino', ctypes.c_ulonglong),  # Inode number
        ('stx_size', ctypes.c_ulonglong),  # Total size in bytes
        ('stx_blocks', ctypes.c_ulonglong),  # Number of 512B blocks allocated
        ('stx_attributes_mask',
         ctypes.c_ulonglong),  # Mask to show what's supported
        # in stx_attributes

        # The following fields are file timestamps
        ('stx_atime', _StructStatxTimestamp),  # Last access
        ('stx_btime', _StructStatxTimestamp),  # Creation
        ('stx_ctime', _StructStatxTimestamp),  # Last status change
        ('stx_mtime', _StructStatxTimestamp),  # Last modification

        # If this file represents a device, then the next two
        # fields contain the ID of the device
        ('stx_rdev_major', ctypes.c_uint),  # Major ID
        ('stx_rdev_minor', ctypes.c_uint),  # Minor ID

        # The next two fields contain the ID of the device
        # containing the filesystem where the file resides
        ('stx_dev_major', ctypes.c_uint),  # Major ID
        ('stx_dev_minor', ctypes.c_uint),  # Minor ID
        ('__statx_pad2', ctypes.c_ulonglong * 14)
    ]


def _stx_timestamp(struct_statx_timestamp):
    """Return statx timestamp."""
    return struct_statx_timestamp.tv_sec + \
        struct_statx_timestamp.tv_nsec * 1e-9


class _Statx(object):
    """statx system call wrapper class."""

    # from kernel-sources include/linux/fcntl.h
    _AT_SYMLINK_NOFOLLOW = 0x100  # Do not follow symbolic links.
    _AT_NO_AUTOMOUNT = 0x800  # Suppress terminal automount traversal
    _AT_FDCWD = -100  # Special value used to indicate
    # openat should use the current working directory.
    _AT_STATX_SYNC_TYPE = 0x6000  # Type of synchronisation required from statx
    _AT_STATX_FORCE_SYNC = 0x2000  # Force the attributes to be sync'd
    # with the server
    _AT_STATX_DONT_SYNC = 0x4000  # Don't sync attributes with the server

    # from kernel-sources include/uapi/linux/stat.h
    _S_IFMT = 0o170000
    _S_IFSOCK = 0o140000
    _S_IFLNK = 0o120000
    _S_IFREG = 0o100000
    _S_IFBLK = 0o60000
    _S_IFDIR = 0o40000
    _S_IFCHR = 0o20000
    _S_IFIFO = 0o10000
    _STATX_TYPE = 0x00000001  # Want/got stx_mode & _S_IFMT
    _STATX_MODE = 0x00000002  # Want/got stx_mode & ~_S_IFMT
    _STATX_NLINK = 0x00000004  # Want/got stx_nlink
    _STATX_UID = 0x00000008  # Want/got stx_uid
    _STATX_GID = 0x00000010  # Want/got stx_gid
    _STATX_ATIME = 0x00000020  # Want/got stx_atime
    _STATX_MTIME = 0x00000040  # Want/got stx_mtime
    _STATX_CTIME = 0x00000080  # Want/got stx_ctime
    _STATX_INO = 0x00000100  # Want/got stx_ino
    _STATX_SIZE = 0x00000200  # Want/got stx_size
    _STATX_BLOCKS = 0x00000400  # Want/got stx_blocks
    _STATX_BASIC_STATS = 0x000007ff  # The stuff in the normal stat struct
    _STATX_BTIME = 0x00000800  # Want/got stx_btime
    _STATX_ALL = 0x00000fff  # All currently supported flagsll

    def __init__(self,
                 filepath,
                 no_automount=False,
                 follow_symlinks=True,
                 get_basic_stats=False,
                 get_filesize_only=False,
                 force_sync=False,
                 dont_sync=False):
        """Construct statx wrapper class."""
        statx_syscall = _get_syscall_func()
        self._dirfd = self._AT_FDCWD
        self._flag = self._AT_SYMLINK_NOFOLLOW
        self._mask = self._STATX_ALL
        if no_automount:
            self._flag |= self._AT_NO_AUTOMOUNT
        if follow_symlinks:
            self._flag &= ~self._AT_SYMLINK_NOFOLLOW
        if get_basic_stats:
            self._mask &= ~self._STATX_BASIC_STATS
        if get_filesize_only:
            self._mask = self._STATX_SIZE
        if force_sync:
            self._flag &= ~self._AT_STATX_SYNC_TYPE
            self._flag |= self._AT_STATX_FORCE_SYNC
        if dont_sync:
            self._flag &= ~self._AT_STATX_SYNC_TYPE
            self._flag |= self._AT_STATX_DONT_SYNC
        self._struct_statx_buf = _StructStatx()
        statx_syscall(self._dirfd, filepath.encode(), self._flag, self._mask,
                      self._struct_statx_buf)

    @property
    def mask(self):
        """Return mask of bits indicating filled fields."""
        return self._struct_statx_buf.stx_mask

    @property
    def st_blksize(self):
        """Return block size for filesystem I/O."""
        return self._struct_statx_buf.stx_blksize

    @property
    def st_nlink(self):
        """Return number of hard links."""
        if self.mask & self._STATX_NLINK:
            return self._struct_statx_buf.stx_nlink
        return None

    @property
    def st_dev(self):
        """Return device ID."""
        return (self._struct_statx_buf.stx_dev_major,
                self._struct_statx_buf.stx_dev_minor)

    @property
    def st_rdev(self):
        """Return file device ID."""
        if self.mask & self._STATX_TYPE:
            file_type = self._struct_statx_buf.stx_mode & self._S_IFMT
            if (file_type == self._S_IFBLK or file_type == self._S_IFCHR):
                return (self._struct_statx_buf.stx_rdev_major,
                        self._struct_statx_buf.stx_rdev_minor)
        return None

    @property
    def st_uid(self):
        """Return user ID of owner."""
        if self.mask & self._STATX_UID:
            return self._struct_statx_buf.stx_uid
        return None

    @property
    def st_gid(self):
        """Return group ID of owner."""
        if self.mask & self._STATX_GID:
            return self._struct_statx_buf.stx_gid
        return None

    @property
    def st_filetype(self):
        """Return file type."""
        if self.mask & self._STATX_TYPE:
            file_type = self._struct_statx_buf.stx_mode & self._S_IFMT
            if file_type == self._S_IFIFO:
                return 'FIFO'
            if file_type == self._S_IFCHR:
                return 'character special file'
            if file_type == self._S_IFDIR:
                return 'directory'
            if file_type == self._S_IFBLK:
                return 'block special file'
            if file_type == self._S_IFREG:
                return 'regular file'
            if file_type == self._S_IFLNK:
                return 'symbolic link'
            if file_type == self._S_IFSOCK:
                return 'socket'
            return 'unknown type {}'.format(
                self._struct_statx_buf.stx_mode & self._S_IFMT)
        return 'no type'

    @property
    def st_mode(self):
        """Return file mode."""
        if self.mask & self._STATX_MODE:
            return self._struct_statx_buf.stx_mode & 0o7777
        return None

    @property
    def st_ino(self):
        """Return inode number."""
        if self.mask & self._STATX_INO:
            return self._struct_statx_buf.stx_ino
        return None

    @property
    def st_size(self):
        """Return total size in bytes."""
        if self.mask & self._STATX_SIZE:
            return self._struct_statx_buf.stx_size
        return None

    @property
    def st_blocks(self):
        """Return number of 512B blocks allocated."""
        if self.mask & self._STATX_BLOCKS:
            return self._struct_statx_buf.stx_blocks
        return None

    @property
    def st_atime(self):
        """Return the last access time."""
        if self.mask & self._STATX_ATIME:
            return _stx_timestamp(self._struct_statx_buf.stx_atime)
        return None

    @property
    def st_btime(self):
        """Return the birth time."""
        if self.mask & self._STATX_BTIME:
            return _stx_timestamp(self._struct_statx_buf.stx_btime)
        return None

    @property
    def st_ctime(self):
        """Return the change time."""
        if self.mask & self._STATX_CTIME:
            return _stx_timestamp(self._struct_statx_buf.stx_ctime)
        return None

    @property
    def st_mtime(self):
        """Return the modification time."""
        if self.mask & self._STATX_MTIME:
            return _stx_timestamp(self._struct_statx_buf.stx_mtime)
        return None


def statx(filepath,
          no_automount=False,
          follow_symlinks=True,
          get_basic_stats=False,
          get_filesize_only=False,
          force_sync=False,
          dont_sync=False):
    """Return statx data buffer object."""
    return _Statx(filepath,
                  no_automount=no_automount,
                  follow_symlinks=follow_symlinks,
                  get_basic_stats=get_basic_stats,
                  get_filesize_only=get_filesize_only,
                  force_sync=force_sync,
                  dont_sync=dont_sync)


def get_btime(filepath):
    try: 
        btime = statx(filepath).st_btime   # Valid for kernel supported Filesystems
    except IOError:
        return "0"
    except OSError:
        return "0"

    #if not btime: # NTFS Support
    #    try:
    #        cmd = "getfattr --only-values -n system.ntfs_times \'{}\'  2>/dev/null | perl -MPOSIX -0777 -ne \'print unpack(Q)/10000000-11644473600\' 2>/dev/null".format(filepath)
    #        stream = os.popen(cmd)
    #        rawbtime = float(stream.read())
    #        btime = "{:14.3f}".format(rawbtime)
    #    except:
    #        return "0"

    return str(btime)

def mode_to_string(mode):
    lookup = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"]
    if S_ISDIR(mode):
        mode_str = "d"
    elif S_ISCHR(mode):
        mode_str = "c"
    elif S_ISBLK(mode):
        mode_str = "b"
    elif S_ISREG(mode):
        mode_str = "-"
    elif S_ISFIFO(mode):
        mode_str = "p"
    elif S_ISLNK(mode):
        mode_str = "l"
    elif S_ISSOCK:
        mode_str = "s"
    own_mode = lookup[(mode & 0o700) >> 6]
    if mode & 0o4000:
        if mode & 0o100:
            own_mode = own_mode.replace("x", "s")
        else:
            own_mode = own_mode[:1] + "S"
    mode_str = mode_str + own_mode
    grp_mode = lookup[(mode & 0o70) >> 3]
    if mode & 0o2000:
        if mode & 0o10:
            grp_mode = grp_mode.replace("x", "s")
        else:
            grp_mode = grp_mode[:1] + "S"
    mode_str = mode_str + own_mode
    oth_mode = lookup[(mode & 0o7)]
    if mode & 0o1000:
        if mode & 0o1:
            oth_mode = oth_mode.replace("x", "t")
        else:
            oth_mode = oth_mode[:1] + "T"
    mode_str = mode_str + oth_mode
    return mode_str


def process_item(dirpath, item, getbirth):
    md5 = hashlib.md5()
    fname = os.path.join(dirpath, item)

    if args.exclude and (fname in args.exclude or dirpath in args.exclude):
        return
    try:
        if os.path.islink(fname):
            status = os.lstat(fname)
        else:
            status = os.stat(fname)
    except IOError:
        return
    except OSError:
        return

    if args.hashes and S_ISREG(status.st_mode):
        try:
            if not (fname.find("/proc/") != -1 and fname.endswith("/kcore")) and status.st_size > 0:
                with open(fname, "rb") as f:
                    if args.size is not None and (status.st_size > args.size):
                        md5str = "0"
                    else:
                        for block in iter(lambda: f.read(65536), b""):
                            md5.update(block)
                        md5str = md5.hexdigest()
            elif status.st_size == 0:
                md5str = "d41d8cd98f00b204e9800998ecf8427e"
            else:
                md5str = "0"
        except IOError:
            md5str = "0"
    else:
        md5str = "0"
    mode = mode_to_string(status.st_mode)
    if os.path.islink(fname) and status.st_size > 0:
        mode = mode + " -> " + os.readlink(fname)
    if sys.version_info < (2, 7, 0):
        mtime = "%14.3f" % (status.mtime)
        atime = "%14.3f" % (status.atime)
        ctime = "%14.3f" % (status.ctime)
    else:
        mtime = "{:14.3f}".format(status.st_mtime)
        atime = "{:14.3f}".format(status.st_atime)
        ctime = "{:14.3f}".format(status.st_ctime)

    btime = "0"
    if getbirth:
        btime=get_btime(fname)

    size = status.st_size
    uid = status.st_uid
    gid = status.st_gid
    inode = status.st_ino
    if args.rmprefix:
        if fname.startswith(args.rmprefix):
            fname = fname[len(args.rmprefix) :]
    if args.prefix:
        if fname.find("/") == 0:
            fname = args.prefix + fname
        else:
            fname = args.prefix + "/" + fname
    return (
        md5str
        + "|"
        + fname
        + "|"
        + str(inode)
        + "|"
        + mode
        + "|"
        + str(uid)
        + "|"
        + str(gid)
        + "|"
        + str(size)
        + "|"
        + atime
        + "|"
        + mtime
        + "|"
        + ctime
        + "|"
        + btime
    )


if sys.version_info < (2, 6, 0):
    sys.stderr.write("Not tested on versions earlier than 2.6\n")
    exit(1)

parser = argparse.ArgumentParser(description="collect data on files")
parser.add_argument("directories", metavar="DIR", nargs="+", help="directories to traverse")
parser.add_argument("-m", "--prefix", metavar="PREFIX", help="prefix string")
parser.add_argument(
    "-s", "--size", metavar="SIZE", type=int, help="max size of file to hash, MACB times collected regardless of size"
)
parser.add_argument(
    "-5", "--hashes", action="store_true", help="do MD5 calculation (disabled by default)", default=False
)
parser.add_argument(
    "-x",
    "--exclude",
    metavar="EXCLUDE",
    action="append",
    help="directory trees or files to exclude, does not handle file extensions or regex",
    default=[],
)
parser.add_argument(
    "-r",
    "--rmprefix",
    metavar="RMPREFIX",
    help="prefix to remove, useful when using read-only --bind mount to prevent atime updates",
)
parser.add_argument(
    "-V",
    "--version",
    action="version",
    help="print version number",
    version="%(prog)s v{version}".format(version=__version__),
)

parser.add_argument(
    "-b",
    "--birth",
    action="store_true",
    help="Try to get birth date",
     default=False,
)

args = parser.parse_args()
if args.size is not None:
    print(args.size)

for directory in args.directories:
    for dirpath, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in args.exclude]
        for directory in dirs:
            outstr = process_item(dirpath, directory, args.birth)
            if outstr is not None:
                print(outstr)
                sys.stdout.flush()
        for filename in files:
            if filename in args.exclude:
                continue
            outstr = process_item(dirpath, filename, args.birth)
            if outstr is not None:
                print(outstr)
                sys.stdout.flush()
