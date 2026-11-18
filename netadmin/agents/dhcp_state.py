"""Cooperative DHCP configuration locks shared by all agent workers."""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path

from netadmin.agents.common import TransactionPathError


@contextmanager
def configuration_lock(main_config: Path) -> Iterator[None]:
    """Keep a stable lock inode across the entire read/modify/activate/rollback flow."""
    lock = main_config.parent.resolve() / ".netadmin-dhcp.lock"
    with ExitStack() as stack:
        descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        stack.callback(os.close, descriptor)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise TransactionPathError("Unsafe DHCP configuration lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        # Closing releases the lock on every exit path. Never unlink the lock:
        # waiters must keep using the same inode rather than a replacement file.
        yield
