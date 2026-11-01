"""Open a file for reading only if it is a regular file, without following a symbolic link
and without blocking on anything else.

Opening a FIFO for reading blocks until a writer appears, so a file is opened
non-blocking, checked to be regular, and only then switched back to blocking reads.
"""

import errno
import fcntl
import os
import stat
from pathlib import Path
from typing import IO


class NotARegularFileError(OSError):
    """The path names a directory, a device, a FIFO, a socket or a symbolic link."""


def open_regular_file(path: Path) -> IO[bytes]:
    """``path`` opened for reading; raises ``NotARegularFileError`` for anything but a
    regular file, and any other ``OSError`` the open raises."""
    try:
        file_descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.EISDIR}:
            raise NotARegularFileError(error.errno, os.strerror(error.errno)) from None
        raise
    try:
        if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
            raise NotARegularFileError(errno.EINVAL, "not a regular file")
        status_flags = fcntl.fcntl(file_descriptor, fcntl.F_GETFL)
        fcntl.fcntl(file_descriptor, fcntl.F_SETFL, status_flags & ~os.O_NONBLOCK)
    except BaseException:
        os.close(file_descriptor)
        raise
    return os.fdopen(file_descriptor, "rb")
