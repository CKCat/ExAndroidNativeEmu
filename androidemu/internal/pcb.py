import os
import sys

from ..vfs.virtual_file import VirtualFile


# 模仿进程控制块信息
# process all info get be get from here including fd etc
class Pcb:
    def __init__(self):
        self._fds = {}
        # Handle redirected streams (e.g., in pytest) where fileno() may not be available
        try:
            stdin_fd = sys.stdin.fileno()
        except Exception:
            stdin_fd = 0  # Standard stdin fd
        try:
            stdout_fd = sys.stdout.fileno()
        except Exception:
            stdout_fd = 1  # Standard stdout fd
        try:
            stderr_fd = sys.stderr.fileno()
        except Exception:
            stderr_fd = 2  # Standard stderr fd

        self._fds[stdin_fd] = VirtualFile("stdin", stdin_fd)
        self._fds[stdout_fd] = VirtualFile("stdout", stdout_fd)
        self._fds[stderr_fd] = VirtualFile("stderr", stderr_fd)

        # Process Identity
        self.uid = 1000
        self.gid = 1000
        self.euid = 1000
        self.egid = 1000

        # Process Args & Env
        self.cmdline = []
        self.environ = {}

        self.signal_handlers = {}

    def get_pid(self):
        return os.getpid()

    def add_fd(self, name, name_in_system, fd, obj=None):
        self._fds[fd] = VirtualFile(name, fd, name_in_system=name_in_system, obj=obj)
        return fd

    def get_fd_detail(self, fd):
        if fd not in self._fds:
            return None
        return self._fds[fd]

    def get_fd_obj(self, fd):
        if fd not in self._fds:
            return None
        return self._fds[fd].obj

    def has_fd(self, fd):
        return fd in self._fds

    def remove_fd(self, fd):
        self._fds.pop(fd)
