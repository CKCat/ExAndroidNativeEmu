import os
import socket
import time
from random import randint
from typing import TYPE_CHECKING

from loguru import logger

from androidemu.cpu.syscall_handlers import SyscallHandlers
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_R0,
    UC_ARM_REG_PC,
    UC_ARM_REG_SP,
    UC_ARM_REG_C13_C0_3,
)
from unicorn.arm64_const import (
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X30,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
)

from .. import config
from ..const import emu_const
from ..const.linux import (
    FUTEX_CMD_MASK,
    FUTEX_WAIT,
    FUTEX_WAIT_BITSET,
    FUTEX_WAKE,
    FUTEX_CMP_REQUEUE,
    FUTEX_WAKE_BITSET,
    CLOCK_REALTIME,
    CLOCK_MONOTONIC,
    CLOCK_MONOTONIC_COARSE,
    SIG_BLOCK,
    SIG_UNBLOCK,
    SIG_SETMASK,
    PR_SET_NAME,
    PR_GET_NAME,
    PR_SET_VMA,
)
from ..utils import memory_helpers

OVERRIDE_TIMEOFDAY = False
OVERRIDE_TIMEOFDAY_SEC = 0
OVERRIDE_TIMEOFDAY_USEC = 0

OVERRIDE_CLOCK = False
OVERRIDE_CLOCK_TIME = 0

if TYPE_CHECKING:
    pass


class SyscallHooks:
    # system call table
    # https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#arm-32_bit_EABI

    def __init__(self, emu, cfg, syscall_handler: SyscallHandlers):
        self.__emu = emu
        self.__ptr_sz = emu.get_ptr_size()
        self._syscall_handler = syscall_handler

        # 统一注册通用的 Handle
        self._register_common_syscalls()

        if self.__emu.get_arch() == emu_const.ARCH_ARM32:
            self._register_arm32_syscalls()
        else:
            self._register_arm64_syscalls()

        self._clock_start = time.time()
        self._clock_offset = randint(50000, 100000)
        # self._sig_maps = {} # Removed, use pcb.signal_handlers
        self.__pcb = self.__emu.get_pcb()
        self.__cfg = cfg
        self._process_name = cfg.get("pkg_name", "com.example.pkg")
        self.__tid_2_tid_addr = {}

    def _register_common_syscalls(self):
        """注册双架构通用的逻辑，减少重复代码"""
        pass

    def _register_arm32_syscalls(self):
        self._syscall_handler.set_handler(0x1, "exit", 1, self.__exit)
        self._syscall_handler.set_handler(0x2, "fork", 0, self.__fork)
        self._syscall_handler.set_handler(0x0B, "execve", 3, self.__execve)
        self._syscall_handler.set_handler(0x14, "getpid", 0, self._getpid)
        self._syscall_handler.set_handler(0x40, "getppid", 0, self._getppid)
        self._syscall_handler.set_handler(0x18, "getuid", 0, self._get_uid)
        self._syscall_handler.set_handler(0x1A, "ptrace", 4, self.__ptrace)
        self._syscall_handler.set_handler(0x25, "kill", 2, self.__kill)
        self._syscall_handler.set_handler(0x2A, "pipe", 1, self.__pipe)
        self._syscall_handler.set_handler(0x36, "ioctl", 3, self._ioctl)
        self._syscall_handler.set_handler(0x37, "fcntl", 3, self._fcntl)
        self._syscall_handler.set_handler(0x43, "sigaction", 3, self._handle_sigaction)
        self._syscall_handler.set_handler(
            0x4E, "gettimeofday", 2, self._handle_gettimeofday
        )
        self._syscall_handler.set_handler(0x72, "wait4", 4, self.__wait4)
        self._syscall_handler.set_handler(0x74, "sysinfo", 1, self.__sysinfo)
        self._syscall_handler.set_handler(0x78, "clone", 5, self.__clone)
        self._syscall_handler.set_handler(0x7A, "uname", 1, self.__uname)
        self._syscall_handler.set_handler(0x7D, "mprotect", 3, self._mprotect)
        self._syscall_handler.set_handler(
            0x7E, "sigprocmask", 3, self._handle_sigprocmask
        )
        self._syscall_handler.set_handler(0xAC, "prctl", 5, self._handle_prctl)
        self._syscall_handler.set_handler(0xAE, "rt_sigaction", 4, self._rt_sigaction)
        self._syscall_handler.set_handler(
            0xAF, "rt_sigprocmask", 4, self._handle_rt_sigprocmask
        )
        self._syscall_handler.set_handler(0xBA, "sigaltstack", 2, self.__sigaltstack)
        self._syscall_handler.set_handler(0xBE, "vfork", 0, self.__vfork)
        self._syscall_handler.set_handler(0xC7, "getuid32", 0, self._get_uid)
        self._syscall_handler.set_handler(
            0xDA, "set_tid_address", 1, self.__set_tid_address
        )
        self._syscall_handler.set_handler(0xDC, "fadvise64_64", 4, self._fadvise64_64)
        self._syscall_handler.set_handler(0xE0, "gettid", 0, self._gettid)
        self._syscall_handler.set_handler(0xF0, "futex", 6, self._handle_futex)
        self._syscall_handler.set_handler(0x10C, "tgkill", 3, self._handle_tgkill)
        self._syscall_handler.set_handler(0xF8, "exit_group", 1, self.__exit_group)
        self._syscall_handler.set_handler(0x94, "fdatasync", 1, self._fdatasync)  # 148
        self._syscall_handler.set_handler(
            0x9E, "sched_yield", 0, self._sched_yield
        )  # 158
        self._syscall_handler.set_handler(0xB7, "getcwd", 2, self._getcwd)  # 183
        self._syscall_handler.set_handler(
            0xFA, "epoll_create", 1, self._epoll_create
        )  # 250
        self._syscall_handler.set_handler(0xFB, "epoll_ctl", 4, self._epoll_ctl)  # 251
        self._syscall_handler.set_handler(
            0xFC, "epoll_wait", 4, self._epoll_wait
        )  # 252

        self._syscall_handler.set_handler(
            0x107, "clock_gettime", 2, self._handle_clock_gettime
        )

        # Network
        self._syscall_handler.set_handler(0x119, "socket", 3, self._socket)
        self._syscall_handler.set_handler(0x11A, "bind", 3, self._bind)
        self._syscall_handler.set_handler(0x11B, "connect", 3, self._connect)
        self._syscall_handler.set_handler(0x11D, "getsockname", 3, self._getsockname)
        self._syscall_handler.set_handler(0x11E, "getpeername", 3, self._getpeername)
        self._syscall_handler.set_handler(0x123, "sendto", 6, self._sendto)
        self._syscall_handler.set_handler(0x124, "recvfrom", 6, self._recvfrom)
        self._syscall_handler.set_handler(0x125, "shutdown", 2, self._shutdown)
        self._syscall_handler.set_handler(0x126, "setsockopt", 5, self._setsockopt)

        self._syscall_handler.set_handler(0x159, "getcpu", 3, self._getcpu)
        self._syscall_handler.set_handler(0x166, "dup3", 3, self.__dup3)
        self._syscall_handler.set_handler(0x167, "pipe2", 2, self.__pipe2)
        self._syscall_handler.set_handler(
            0x178, "process_vm_readv", 6, self.__process_vm_readv
        )
        self._syscall_handler.set_handler(0x180, "getrandom", 3, self._getrandom)
        self._syscall_handler.set_handler(0xD0, "tkill", 2, self._handle_tkill)
        self._syscall_handler.set_handler(
            0xF0002, "ARM_cacheflush", 0, self._ARM_cacheflush
        )
        self._syscall_handler.set_handler(0xF0005, "ARM_set_tls", 1, self._ARM_set_tls)
        self._syscall_handler.set_handler(0xA2, "nanosleep", 2, self._nanosleep)
        self._syscall_handler.set_handler(0x163, "prlimit64", 4, self._prlimit64)
        # ARM32 rt_sigreturn = 173
        self._syscall_handler.set_handler(0xAD, "rt_sigreturn", 0, self._rt_sigreturn)

    def _register_arm64_syscalls(self):
        self._syscall_handler.set_handler(0x17, "dup", 1, self.__dup)
        self._syscall_handler.set_handler(0x18, "dup3", 3, self.__dup3)
        self._syscall_handler.set_handler(0x1D, "ioctl", 3, self._ioctl)
        self._syscall_handler.set_handler(0x19, "fcntl", 3, self._fcntl)
        self._syscall_handler.set_handler(0x3B, "pipe2", 2, self.__pipe2)
        self._syscall_handler.set_handler(0x5D, "exit", 1, self.__exit)
        self._syscall_handler.set_handler(0x5E, "exit_group", 1, self.__exit_group)
        self._syscall_handler.set_handler(0x11, "getcwd", 2, self._getcwd)
        self._syscall_handler.set_handler(0x14, "epoll_create1", 1, self._epoll_create1)
        self._syscall_handler.set_handler(0x15, "epoll_ctl", 4, self._epoll_ctl)
        self._syscall_handler.set_handler(
            0x16, "epoll_pwait", 5, self._epoll_pwait
        )  # Note: 5 args? timeout usually 4th, sigmask 5th
        self._syscall_handler.set_handler(
            0x18, "dup3", 3, self.__dup3
        )  # 24 for fdatasync?
        self._syscall_handler.set_handler(0x53, "fdatasync", 1, self._fdatasync)  # 83
        self._syscall_handler.set_handler(
            0x7C, "sched_yield", 0, self._sched_yield
        )  # 124
        self._syscall_handler.set_handler(0x1D, "ioctl", 3, self._ioctl)
        self._syscall_handler.set_handler(0xDD, "execve", 3, self.__execve)
        self._syscall_handler.set_handler(0xAC, "getpid", 0, self._getpid)
        self._syscall_handler.set_handler(0xAD, "getppid", 0, self._getppid)
        self._syscall_handler.set_handler(0xAE, "getuid", 0, self._get_uid)
        self._syscall_handler.set_handler(0x75, "ptrace", 4, self.__ptrace)
        self._syscall_handler.set_handler(0x81, "kill", 2, self.__kill)
        self._syscall_handler.set_handler(
            0xA9, "gettimeofday", 2, self._handle_gettimeofday
        )
        self._syscall_handler.set_handler(0xE2, "mprotect", 3, self._mprotect)
        self._syscall_handler.set_handler(0xE9, "madvise", 3, self._madvise)
        self._syscall_handler.set_handler(0x104, "wait4", 4, self.__wait4)
        self._syscall_handler.set_handler(0xB3, "sysinfo", 1, self.__sysinfo)
        self._syscall_handler.set_handler(0xDC, "clone", 5, self.__clone)
        self._syscall_handler.set_handler(0xA0, "uname", 1, self.__uname)
        self._syscall_handler.set_handler(0xA7, "prctl", 5, self._handle_prctl)
        self._syscall_handler.set_handler(0x86, "rt_sigaction", 4, self._rt_sigaction)
        self._syscall_handler.set_handler(
            0x87, "rt_sigprocmask", 4, self._handle_rt_sigprocmask
        )
        self._syscall_handler.set_handler(0x84, "sigaltstack", 2, self.__sigaltstack)
        # ARM64 rt_sigreturn = 139 (0x8B)
        self._syscall_handler.set_handler(0x8B, "rt_sigreturn", 0, self._rt_sigreturn)
        self._syscall_handler.set_handler(0xB2, "gettid", 0, self._gettid)
        self._syscall_handler.set_handler(0x105, "prlimit64", 4, self._prlimit64)
        self._syscall_handler.set_handler(0x105, "prlimit64", 4, self._prlimit64)
        self._syscall_handler.set_handler(0x62, "futex", 6, self._handle_futex)
        self._syscall_handler.set_handler(0x83, "tgkill", 3, self._handle_tgkill)
        self._syscall_handler.set_handler(0x82, "tkill", 2, self._handle_tkill)
        self._syscall_handler.set_handler(
            0x71, "clock_gettime", 2, self._handle_clock_gettime
        )

        # Network
        self._syscall_handler.set_handler(0xC6, "socket", 3, self._socket)
        self._syscall_handler.set_handler(0xC8, "bind", 3, self._bind)
        self._syscall_handler.set_handler(0xCB, "connect", 3, self._connect)
        self._syscall_handler.set_handler(0xCC, "getsockname", 3, self._getsockname)
        self._syscall_handler.set_handler(0xCD, "getpeername", 3, self._getpeername)
        self._syscall_handler.set_handler(0xD3, "shutdown", 2, self._shutdown)
        self._syscall_handler.set_handler(0xD0, "setsockopt", 5, self._setsockopt)
        self._syscall_handler.set_handler(0xCE, "sendto", 6, self._sendto)
        self._syscall_handler.set_handler(0xCF, "recvfrom", 6, self._recvfrom)

        self._syscall_handler.set_handler(0xA8, "getcpu", 3, self._getcpu)
        self._syscall_handler.set_handler(
            0x10E, "process_vm_readv", 6, self.__process_vm_readv
        )
        self._syscall_handler.set_handler(0x116, "getrandom", 3, self._getrandom)
        self._syscall_handler.set_handler(0x65, "nanosleep", 2, self._nanosleep)

    def __do_fork(self, mu):
        # 修正：在Unicorn中进行os.fork()通常是不安全的，因为内存状态无法完美复制。
        # 更好的做法是"Fake Fork"，即返回一个假的PID给调用者，假装你是父进程，
        # 或者返回0假装你是子进程。大多数反调试检查只要返回值大于0即可。
        logger.warning("fake fork called, returning fake PID 10086")
        return 10086

    def __exit(self, mu, err_code):
        sch = self.__emu.get_schduler()
        cur_tid = sch.get_current_tid()
        if cur_tid in self.__tid_2_tid_addr:
            tid_addr_futex = self.__tid_2_tid_addr[cur_tid]
            sch.futex_wake(tid_addr_futex)
            mu.mem_write(tid_addr_futex, int(0).to_bytes(4, byteorder="little"))
            self.__tid_2_tid_addr.pop(cur_tid)
        sch.exit_current_task()
        return 0

    def __exit_group(self, mu, err_code):
        logger.info(f"exit_group({err_code}) called. Terminating emulation.")
        # 清除所有任务，实际上停止模拟
        sch = self.__emu.get_schduler()
        # 这里可以直接 raise exception 或调用 scheduler 的特殊方法
        # 目前简单暴力一点，清除所有 task map
        # sch.terminate() # 如果有这个方法
        # 或者直接抛出 StopEmulation
        # 这里我们手动清除
        # 这会导致 scheduler 循环结束
        # 更好的方式可能是通知 scheduler 停止
        sch.yield_task()
        # Hack: clear tasks
        # Accessing private members is bad but scheduler API is limited
        sch._Scheduler__tasks_map.clear()
        sch._Scheduler__ordered_tasks_list.clear()
        return 0

    def __fork(self, mu):
        return self.__do_fork(mu)

    def __execve(self, mu, filename_ptr, argv_ptr, envp_ptr):
        filename = memory_helpers.read_utf8(mu, filename_ptr)
        params = []
        ptr = argv_ptr
        if ptr != 0:
            while True:
                off = memory_helpers.read_ptr_sz(mu, ptr, self.__ptr_sz)
                if off == 0:
                    break
                param = memory_helpers.read_utf8(mu, off)
                params.append(param)
                ptr += self.__emu.get_ptr_size()

        logger.warning("execve %s %r" % (filename, params))
        cmd = " ".join(params)
        pkg_name = self.__cfg.get("pkg_name", "com.example.pkg")

        # 模拟常见命令输出
        if "pm path" in cmd:
            output = f"package:/data/app/{pkg_name}-1.apk"
        elif "wm density" in cmd:
            output = "Physical density: 420"
        elif "wm size" in cmd:
            output = "Physical size: 1080x1920"
        elif "adbd" in cmd:
            output = ""
        elif "which su" in cmd:  # 常见反调试
            return -1  # Not found
        else:
            logger.info(f"Unhandled execve cmd: {cmd}, returning 0")
            return 0

        logger.debug("write to stdout [%s]" % output)
        os.write(1, output.encode("utf-8"))
        # 注意：这里不能sys.exit，否则模拟器就退出了
        # 实际上 execve 会替换当前进程映像，这里我们只模拟执行了命令并返回成功
        return 0

    def _getpid(self, mu):
        return self.__pcb.get_pid()

    def _getppid(self, mu):
        return self.__pcb.get_pid() - 1 if self.__pcb.get_pid() > 1 else 1

    def __ptrace(self, mu, request, pid, addr, data):
        # 0 = PTRACE_TRACEME
        if request == 0:
            logger.info("ptrace PTRACE_TRACEME called")
            return 0
        logger.warning("skip syscall ptrace request [%d] pid [0x%x]" % (request, pid))
        return 0

    def __kill(self, mu, pid, sig):
        logger.warning("kill is call pid=0x%x sig=%d" % (pid, sig))
        if pid == self._getpid(mu):
            logger.error("Process killing itself, possible anti-debug triggered!")
            # 可以在这里抛出异常停止模拟
        return 0

    def __pipe_common(self, mu, files_ptr, flags):
        try:
            r, w = os.pipe()
            self.__pcb.add_fd("[pipe_r]", "[pipe_r]", r)
            self.__pcb.add_fd("[pipe_w]", "[pipe_w]", w)
            mu.mem_write(files_ptr, int(r).to_bytes(4, byteorder="little"))
            mu.mem_write(files_ptr + 4, int(w).to_bytes(4, byteorder="little"))
            return 0
        except Exception as e:
            logger.error(f"pipe creation failed: {e}")
            return -1

    def __pipe(self, mu, files_ptr):
        return self.__pipe_common(mu, files_ptr, 0)

    def _ioctl(self, mu, fd, request, argp):
        logger.debug(f"ioctl called fd={fd} req=0x{request:x} arg=0x{argp:x}")
        # 这里很难通用实现，通常返回0表示成功即可骗过很多检测
        return 0

    def _fcntl(self, mu, fd, cmd, arg):
        logger.debug(f"fcntl called fd={fd} cmd={cmd} arg={arg}")
        # F_GETFL = 3, F_SETFL = 4
        if cmd == 3:
            return 0  # 假设没有特殊 flag
        if cmd == 4:
            return 0  # 假装设置成功
        return 0

    def _handle_sigaction(self, mu, sig, act, oact):
        if act != 0:
            act_off = act
            sa_handler = memory_helpers.read_ptr_sz(mu, act_off, self.__ptr_sz)
            self.__pcb.signal_handlers[sig] = sa_handler
            logger.debug(f"sigaction sig={sig} handler=0x{sa_handler:x}")
        return 0

    def _rt_sigaction(self, mu, sig, act, oact, sigsetsize):
        return self._handle_sigaction(mu, sig, act, oact)

    def _gettid(self, mu):
        sch = self.__emu.get_schduler()
        return sch.get_current_tid()

    def _getcpu(self, mu, _cpu, node, cache):
        if _cpu != 0:
            mu.mem_write(_cpu, int(0).to_bytes(4, byteorder="little"))
        if node != 0:
            mu.mem_write(node, int(0).to_bytes(4, byteorder="little"))
        return 0

    def _handle_gettimeofday(self, uc, tv, tz):
        if tv != 0:
            ptr_sz = self.__emu.get_ptr_size()
            if OVERRIDE_TIMEOFDAY:
                sec, usec = OVERRIDE_TIMEOFDAY_SEC, OVERRIDE_TIMEOFDAY_USEC
            else:
                timestamp = time.time()
                sec = int(timestamp)
                usec = int((timestamp - sec) * 1_000_000)

            uc.mem_write(tv, int(sec).to_bytes(ptr_sz, "little"))
            uc.mem_write(tv + ptr_sz, int(usec).to_bytes(ptr_sz, "little"))

        if tz != 0:
            uc.mem_write(tz, int(-480).to_bytes(4, "little"))  # China Standard Time
            uc.mem_write(tz + 4, int(0).to_bytes(4, "little"))
        return 0

    def __wait4(self, mu, pid, wstatus, options, ru):
        # 简单模拟，直接返回子进程已结束
        logger.debug(f"wait4 pid={pid}")
        if wstatus != 0:
            mu.mem_write(wstatus, int(0).to_bytes(4, "little"))
        return pid

    def __sysinfo(self, mu, info_ptr):
        # 填充一些假数据
        uptime = int(time.time() - self._clock_start)
        is_64 = self.__emu.get_arch() == emu_const.ARCH_ARM64
        ulong_sz = 8 if is_64 else 4

        def write_ulong(off, val):
            mu.mem_write(info_ptr + off, int(val).to_bytes(ulong_sz, "little"))
            return off + ulong_sz

        off = 0
        off = write_ulong(off, uptime)
        off = write_ulong(off, 503328)  # loads[0]
        off = write_ulong(off, 503328)
        off = write_ulong(off, 503328)
        off = write_ulong(off, 2 * 1024 * 1024 * 1024)  # totalram
        off = write_ulong(off, 100 * 1024 * 1024)  # freeram
        off = write_ulong(off, 0)  # sharedram
        off = write_ulong(off, 0)  # bufferram
        off = write_ulong(off, 0)  # totalswap
        off = write_ulong(off, 0)  # freeswap
        mu.mem_write(info_ptr + off, int(500).to_bytes(2, "little"))  # procs
        return 0

    def __clone(self, mu, flags, child_stack, arg3, arg4, arg5):
        # 这是一个极度简化的 clone 实现，仅支持创建线程的基本逻辑

        # Determine args based on arch
        if self.__emu.get_arch() == emu_const.ARCH_ARM64:
            # clone(flags, stack, ptid, tls, ctid)
            parent_tid = arg3
            tls_ptr = arg4
            child_tid_ptr = arg5
        else:
            # clone(flags, stack, ptid, tls, ctid)
            parent_tid = arg3
            tls_ptr = arg4
            child_tid_ptr = arg5

        CLONE_THREAD = 0x00010000
        CLONE_SETTLS = 0x00080000
        CLONE_PARENT_SETTID = 0x00100000
        CLONE_CHILD_CLEARTID = 0x00200000
        CLONE_CHILD_SETTID = 0x01000000

        if flags & CLONE_THREAD:
            logger.info("clone: creating thread")
            sch = self.__emu.get_schduler()

            set_tls = 0
            if flags & CLONE_SETTLS:
                set_tls = tls_ptr

            # 创建子任务
            tid = sch.add_sub_task(child_stack, set_tls)

            # 处理 TID 回写
            if (flags & CLONE_PARENT_SETTID) and parent_tid != 0:
                mu.mem_write(parent_tid, tid.to_bytes(4, "little"))

            if (flags & CLONE_CHILD_SETTID) and child_tid_ptr != 0:
                mu.mem_write(child_tid_ptr, tid.to_bytes(4, "little"))

            # 记录用于 FUTEX 唤醒的地址
            if (flags & CLONE_CHILD_CLEARTID) and child_tid_ptr != 0:
                self.__tid_2_tid_addr[tid] = child_tid_ptr

            # 调度一次让子线程跑起来
            sch.yield_task()
            return tid
        else:
            logger.warning(f"clone: performing fork-like clone flags=0x{flags:x}")
            return self.__do_fork(mu)

    def _handle_prctl(self, mu, option, arg2, arg3, arg4, arg5):
        if option == PR_SET_NAME:
            name = memory_helpers.read_utf8(mu, arg2)
            self._process_name = name
            logger.debug(f"prctl set name: {name}")
            return 0
        elif option == PR_GET_NAME:
            memory_helpers.write_utf8(mu, arg2, self._process_name)
            return 0
        elif option == PR_SET_VMA:
            # Android specific: set VMA name for debugging
            # arg2 is the sub-option (typically 0 for PR_SET_VMA_ANON_NAME)
            # arg3 is the start address, arg4 is the length, arg5 is the name pointer
            # We just pretend success, as this is purely for debugging/tooling
            logger.debug(f"prctl PR_SET_VMA: addr=0x{arg3:x} len=0x{arg4:x}")
            return 0
        return 0

    def __uname(self, mu, buf):
        memory_helpers.write_utf8(mu, buf, "Linux")
        memory_helpers.write_utf8(mu, buf + 65, "localhost")
        memory_helpers.write_utf8(mu, buf + 130, "4.14.113+")
        memory_helpers.write_utf8(
            mu, buf + 195, "#1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 2020"
        )
        memory_helpers.write_utf8(
            mu,
            buf + 260,
            "aarch64" if self.__emu.get_arch() == emu_const.ARCH_ARM64 else "armv7l",
        )
        return 0

    def _handle_sigprocmask(self, mu, how, set_ptr, oset_ptr):
        return self._handle_rt_sigprocmask(mu, how, set_ptr, oset_ptr, 8)

    def _handle_rt_sigprocmask(self, mu, how, set_ptr, oset_ptr, sigsetsize):
        logger.debug(
            f"rt_sigprocmask how={how} set={set_ptr:x} oset={oset_ptr:x} size={sigsetsize}"
        )
        sch = self.__emu.get_schduler()
        tid = sch.get_current_tid()
        old_mask = sch.get_signal_mask(tid)

        if oset_ptr != 0:
            # Write old mask
            # Assuming sigsetsize is sufficient for the mask we track (integer)
            # Cap at 8 bytes
            sz = min(sigsetsize, 8)
            mu.mem_write(oset_ptr, int(old_mask).to_bytes(sz, "little"))

        if set_ptr != 0:
            sz = min(sigsetsize, 8)
            new_set_bytes = mu.mem_read(set_ptr, sz)
            new_set = int.from_bytes(new_set_bytes, "little")

            new_mask = old_mask
            if how == SIG_BLOCK:
                new_mask |= new_set
            elif how == SIG_UNBLOCK:
                new_mask &= ~new_set
            elif how == SIG_SETMASK:
                new_mask = new_set
            else:
                logger.warning(f"rt_sigprocmask unknown how {how}")
                return -22  # EINVAL

            sch.set_signal_mask(tid, new_mask)

        return 0

    def __sigaltstack(self, mu, uss, ouss):
        logger.debug("sigaltstack called")
        # 假装成功，不实际修改栈
        return 0

    def __vfork(self, mu):
        return self.__do_fork(mu)

    def _get_uid(self, mu):
        return self.__cfg.get("uid", 1000)

    def __set_tid_address(self, mu, tidptr):
        sch = self.__emu.get_schduler()  # 修复：添加括号调用方法
        tid = sch.get_current_tid()
        if tidptr == 0:
            if tid in self.__tid_2_tid_addr:
                self.__tid_2_tid_addr.pop(tid)
        else:
            self.__tid_2_tid_addr[tid] = tidptr
        return tid

    def _fadvise64_64(self, mu, fd, offset, len, advice):
        return 0

    def _mprotect(self, mu, addr, len, prot):
        logger.debug(f"mprotect addr=0x{addr:x} len=0x{len:x} prot={prot}")
        # Align to page boundaries
        page_size = 0x1000
        addr_aligned = addr & ~(page_size - 1)
        # Calculate new length to cover the range
        end_addr = (addr + len + page_size - 1) & ~(page_size - 1)
        len_aligned = end_addr - addr_aligned

        try:
            mu.mem_protect(addr_aligned, len_aligned, prot)
            return 0
        except Exception as e:
            logger.error(f"mprotect failed: {e}")
            return -1

    def _madvise(self, mu, addr, len, advice):
        return 0

    def _handle_futex(self, mu, uaddr, op, val, timeout_ptr, uaddr2, val3):
        # 这里的实现依赖于调度器的支持
        cmd = op & FUTEX_CMD_MASK
        sch = self.__emu.get_schduler()

        # 读取当前内存中的值
        try:
            curr_val_bytes = mu.mem_read(uaddr, 4)
            curr_val = int.from_bytes(curr_val_bytes, "little")
        except Exception:
            return -1  # EFAULT

        if cmd == FUTEX_WAIT or cmd == FUTEX_WAIT_BITSET:
            if curr_val != val:
                return -1  # EAGAIN

            timeout_ms = -1
            if timeout_ptr != 0:
                ts_sec = memory_helpers.read_ptr_sz(mu, timeout_ptr, self.__ptr_sz)
                ts_nsec = memory_helpers.read_ptr_sz(
                    mu, timeout_ptr + self.__ptr_sz, self.__ptr_sz
                )
                timeout_ms = (ts_sec * 1000) + (ts_nsec // 1000000)

            logger.debug(
                f"futex wait addr=0x{uaddr:x} val={val} timeout={timeout_ms}ms"
            )
            sch.futex_wait(uaddr, timeout_ms)
            return 0

        elif cmd == FUTEX_CMP_REQUEUE:
            # val: num of waiters to wake
            # val3: val3 (arg 6) is val3 for CMP_REQUEUE, but for syscall argument mapping,
            # val3 is typically passed in r5/x5. Wait.
            # syscall handlers signature: mu, uaddr, op, val, timeout_ptr, uaddr2, val3
            # man futex: futex(uaddr, FUTEX_CMP_REQUEUE, val, val2, uaddr2, val3)
            # here arguments map:
            # uaddr -> uaddr
            # op -> op
            # val -> val (num wake)
            # timeout_ptr -> val2 (num requeue) !!!! (This is tricky, timeout_ptr argument holds val2 in this case)
            # uaddr2 -> uaddr2
            # val3 -> val3

            val2 = timeout_ptr  # In CMP_REQUEUE, arg4 is val2 (limit of requeue)

            logger.debug(
                f"futex cmp_requeue addr=0x{uaddr:x} val={val} val2={val2} addr2=0x{uaddr2:x} cmp={val3}"
            )

            # Check value at uaddr
            if curr_val != val3:
                return -1  # EAGAIN

            # Wake up to val waiters
            nwaken = 0
            for _ in range(val):
                if sch.futex_wake(uaddr):
                    nwaken += 1
                else:
                    break

            # Requeue up to val2 waiters
            nrequeued = 0
            for _ in range(val2):
                if sch.futex_requeue(uaddr, uaddr2):
                    nrequeued += 1
                else:
                    break

            sch.yield_task()
            return nwaken + nrequeued

        elif cmd == FUTEX_WAKE or cmd == FUTEX_WAKE_BITSET:
            logger.debug(f"futex wake addr=0x{uaddr:x} val={val}")
            nwake = 0
            for _ in range(val):
                if sch.futex_wake(uaddr):
                    nwake += 1
                else:
                    break
            sch.yield_task()
            return nwake

        return 0

    def _handle_tgkill(self, mu, tgid, tid, sig):
        logger.debug(f"tgkill: tgid={tgid} tid={tid} sig={sig}")

        # Check integrity
        # If tgid != -1 and tgid != pid, permission denied?
        # But we only emulate one process usually.

        # Dispatch signal to target thread
        # We need to find the task by tid.
        sch = self.__emu.get_schduler()
        # Note: We can't easily interrupt another thread if we are single threaded in python loop.
        # But we can set a pending signal flag on the PCB/Thread.

        # Check if handler exists
        handlers = self.__emu.get_pcb().signal_handlers
        if sig in handlers:
            handler_addr = handlers[sig]
            logger.info(
                f"tgkill: Dispatching signal {sig} to tid {tid} handler 0x{handler_addr:x}"
            )

            # If target is current thread, we can setup immediately (maybe?)
            if tid == sch.get_current_tid():
                self.setup_signal_frame(tid, sig, handler_addr)
            else:
                # Signal queuing for other threads is complex in this emulation model.
                # Since we don't have true concurrency with preemptive switching,
                # we can't easily interrupt the other thread's execution loop.
                # For now, we log warning and ignore, assuming cooperative yielding or checks elsewhere.
                logger.warning(
                    f"tgkill: Signal queuing for other tid {tid} not fully implemented. Ignoring."
                )
        else:
            if sig == 6:  # SIGABRT
                logger.error(
                    f"tgkill: Process aborting (SIGABRT) tid={tid}, no handler."
                )
                # We should probably exit or stop emulation
            else:
                logger.debug(f"tgkill: Signal {sig} ignored (no handler)")

        return 0

    def _handle_tkill(self, mu, tid, sig):
        # tkill is like tgkill but tgid is implied
        return self._handle_tgkill(mu, -1, tid, sig)

    def _fdatasync(self, mu, fd):
        return 0

    def _getcwd(self, mu, buf, size):
        path = "/"
        b = path.encode("utf-8") + b"\0"
        if len(b) > size:
            return -34  # ERANGE
        mu.mem_write(buf, b)
        return len(b)

    def _epoll_create(self, mu, size):
        return 100

    def _epoll_create1(self, mu, flags):
        return 100

    def _epoll_ctl(self, mu, epfd, op, fd, event):
        return 0

    def _epoll_wait(self, mu, epfd, events, maxevents, timeout):
        return 0

    def _epoll_pwait(self, mu, epfd, events, maxevents, timeout, sigmask):
        return 0

    def _handle_clock_gettime(self, mu, clk_id, tp_ptr):
        sec, nsec = 0, 0
        if clk_id == CLOCK_REALTIME:
            t = time.time()
            sec = int(t)
            nsec = int((t - sec) * 1e9)
        elif clk_id in [CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE]:
            t = time.time() - self._clock_start
            sec = int(t)
            nsec = int((t - sec) * 1e9)

        if tp_ptr != 0:
            mu.mem_write(tp_ptr, int(sec).to_bytes(self.__ptr_sz, "little"))
            mu.mem_write(
                tp_ptr + self.__ptr_sz,
                int(nsec).to_bytes(self.__ptr_sz, "little"),
            )
        return 0

    def _sched_yield(self, mu):
        self.__emu.get_schduler().yield_task()
        return 0

    # ================= Network Syscalls Implementations =================

    def _prlimit64(self, mu, pid, resource, new_limit, old_limit):
        logger.debug(
            f"prlimit64(pid={pid}, resource={resource}, new=0x{new_limit:x}, old=0x{old_limit:x})"
        )

        if old_limit != 0:
            # Write current limits.
            # Lets say 1024 soft, 4096 hard for files? Or unlimited?
            # For now use RLIM_INFINITY? (0xffffffffffffffff)
            # But some apps check this.
            # 1024 is safer default for NOFILE.
            cur = 1024
            max_ = 4096

            # Simple default
            mu.mem_write(old_limit, int(cur).to_bytes(8, "little"))
            mu.mem_write(old_limit + 8, int(max_).to_bytes(8, "little"))

        return 0

    def _read_sockaddr(self, mu, addr, addr_len):
        """解析 sockaddr 结构体"""
        if addr == 0 or addr_len < 2:
            return None, None

        family_bytes = mu.mem_read(addr, 2)
        family = int.from_bytes(family_bytes, "little")

        if family == 2:  # AF_INET
            if addr_len < 8:
                return None, None
            port_bytes = mu.mem_read(addr + 2, 2)
            port = int.from_bytes(port_bytes, "big")
            ip_bytes = mu.mem_read(addr + 4, 4)
            ip = socket.inet_ntoa(ip_bytes)
            return family, (ip, port)
        elif family == 10:  # AF_INET6
            # 暂不支持 IPv6 解析，返回空占位
            return family, None

        return family, None

    def _socket(self, mu, domain, type_in, protocol):
        try:
            # 映射 Android 常量到 Python socket 模块
            # AF_INET=2, AF_INET6=10
            # SOCK_STREAM=1, SOCK_DGRAM=2
            py_family = socket.AF_INET if domain == 2 else socket.AF_INET6
            py_type = socket.SOCK_STREAM if type_in & 0xF == 1 else socket.SOCK_DGRAM

            s = socket.socket(py_family, py_type, protocol)
            # 设置非阻塞以防止模拟器卡死，虽然应用层可能设置回去
            s.setblocking(False)

            fd = s.fileno()
            # 关键：一定要把 socket 对象保存在 Python 侧，防止被 GC 关闭
            self.__pcb.add_fd(f"socket:[{fd}]", "socket", fd, obj=s)
            logger.debug(f"socket created fd={fd} domain={domain} type={type_in}")
            return fd
        except Exception as e:
            logger.error(f"socket create failed: {e}")
            return -1

    def _connect(self, mu, fd, addr, addr_len):
        family, py_addr = self._read_sockaddr(mu, addr, addr_len)
        logger.debug(f"connect fd={fd} addr={py_addr}")

        sock = self.__pcb.get_fd_obj(fd)  # 假设 PCB 有 get_fd_obj 方法获取 Python 对象
        if not sock:
            # 兼容：如果 PCB 没存对象，尝试用 fd 恢复（如果是真实文件描述符）
            try:
                sock = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
            except Exception:
                return -9  # EBADF

        if py_addr:
            try:
                sock.setblocking(True)  # Connect 暂时阻塞
                sock.connect(py_addr)
                sock.setblocking(False)
                return 0
            except socket.error as e:
                logger.debug(f"connect failed: {e}")
                return -1
        return 0

    def _bind(self, mu, fd, addr, addr_len):
        family, py_addr = self._read_sockaddr(mu, addr, addr_len)
        logger.debug(f"bind fd={fd} addr={py_addr}")
        sock = self.__pcb.get_fd_obj(fd)
        if sock and py_addr:
            try:
                sock.bind(py_addr)
                return 0
            except Exception as e:
                logger.error(f"bind error: {e}")
                return -1
        return 0

    def _getsockname(self, mu, fd, addr, addr_len_ptr):
        # 简单实现：不写回真实 IP，因为很多时候只是为了获取 buffer
        # 如果需要真实实现，需要从 sock 对象获取 getsockname() 并序列化回内存
        logger.debug(f"getsockname fd={fd}")
        return 0

    def _getpeername(self, mu, fd, addr, addr_len_ptr):
        logger.debug(f"getpeername fd={fd}")
        return 0

    def _setsockopt(self, mu, fd, level, optname, optval, optlen):
        # 忽略所有 setsockopt，返回成功
        logger.debug(f"setsockopt fd={fd} level={level} optname={optname}")
        return 0

    def _sendto(self, mu, fd, buf, count, flags, dest_addr, addrlen):
        # 简化处理：忽略 dest_addr，当作 send 处理
        sock = self.__pcb.get_fd_obj(fd)
        data = memory_helpers.read_byte_array(mu, buf, count)
        if sock:
            try:
                sent = sock.send(data)
                return sent
            except BlockingIOError:
                return -11  # EAGAIN
            except Exception as e:
                logger.error(f"sendto error: {e}")
        return count  # 假装发送成功

    def _recvfrom(self, mu, fd, buf, count, flags, src_addr, addrlen):
        sock = self.__pcb.get_fd_obj(fd)
        if sock:
            try:
                data = sock.recv(count)
                if data:
                    mu.mem_write(buf, data)
                    return len(data)
            except BlockingIOError:
                return -11  # EAGAIN
            except Exception as e:
                logger.error(f"recvfrom error: {e}")
        return -11  # EAGAIN 假装没数据

    def _shutdown(self, mu, fd, how):
        sock = self.__pcb.get_fd_obj(fd)
        if sock:
            try:
                sock.shutdown(how)
                return 0
            except Exception:
                pass
        return 0

    def __dup(self, mu, oldfd):
        try:
            newfd = os.dup(oldfd)
            old_obj = self.__pcb.get_fd_obj(oldfd)
            self.__pcb.add_fd(f"dup[{newfd}]", "dup", newfd, obj=old_obj)
            return newfd
        except Exception:
            return -1

    def __dup3(self, mu, oldfd, newfd, flags):
        try:
            os.dup2(oldfd, newfd)
            # 同时复制 PCB 中的记录
            old_obj = self.__pcb.get_fd_obj(oldfd)
            self.__pcb.add_fd(f"dup[{newfd}]", "dup", newfd, obj=old_obj)
            return newfd
        except Exception:
            return -1

    def __pipe2(self, mu, files_ptr, flags):
        return self.__pipe_common(mu, files_ptr, flags)

    def _getrandom(self, mu, buf, count, flags):
        # 返回随机字节
        rand_bytes = os.urandom(count)
        mu.mem_write(buf, rand_bytes)
        return count

    def __process_vm_readv(
        self, mu, pid, local_iov, liovcnt, remote_iov, riovcnt, flag
    ):
        if pid != self._getpid(mu):
            logger.warning("process_vm_readv for other PID not supported")
            return -1

        # 1. 读取远程（其实是自己的）内存到 buffer
        total_data = bytearray()
        off_r = remote_iov
        for _ in range(riovcnt):
            rbase = memory_helpers.read_ptr_sz(mu, off_r, self.__ptr_sz)
            iov_len = memory_helpers.read_ptr_sz(
                mu, off_r + self.__ptr_sz, self.__ptr_sz
            )
            curr_read = memory_helpers.read_byte_array(mu, rbase, iov_len)
            total_data.extend(curr_read)
            off_r += 2 * self.__ptr_sz

        # 2. 将 buffer 写入本地（local_iov）
        off_l = local_iov
        bytes_written = 0
        current_data_idx = 0

        for _ in range(liovcnt):
            if current_data_idx >= len(total_data):
                break

            lbase = memory_helpers.read_ptr_sz(mu, off_l, self.__ptr_sz)
            liov_len = memory_helpers.read_ptr_sz(
                mu, off_l + self.__ptr_sz, self.__ptr_sz
            )

            # 计算这次能写多少
            chunk_size = min(liov_len, len(total_data) - current_data_idx)
            chunk = total_data[current_data_idx : current_data_idx + chunk_size]

            mu.mem_write(lbase, bytes(chunk))

            current_data_idx += chunk_size
            bytes_written += chunk_size
            off_l += 2 * self.__ptr_sz

        return bytes_written

    def _ARM_cacheflush(self, mu):
        return 0

    def _ARM_set_tls(self, mu, tls_ptr):
        self.__emu.mu.reg_write(UC_ARM_REG_C13_C0_3, tls_ptr)
        return 0

    def _rt_sigreturn(self, mu):
        logger.debug("rt_sigreturn called")
        self.restore_signal_frame(mu)
        return 0

    def setup_signal_frame(self, tid, signal, handler_addr, restorer_addr=0):
        # Determine Arch
        arch = self.__emu.get_arch()
        arch = self.__emu.get_arch()
        # mu is self.__emu.mu
        mu = self.__emu.mu
        sp_reg = 0
        pc_reg = 0
        if arch == emu_const.ARCH_ARM32:
            sp_reg = UC_ARM_REG_SP
            pc_reg = UC_ARM_REG_PC
        else:
            sp_reg = UC_ARM64_REG_SP
            pc_reg = UC_ARM64_REG_PC

        sp = mu.reg_read(sp_reg)
        pc = mu.reg_read(pc_reg)

        # We need to save enough context to restore later.
        # Simplified frame:
        # [SP-8]  = Magic Cookie
        # [SP-16] = PC
        # [SP-24] = Saved R0 / X0
        # ...
        # For full correctness we need all regs.
        # But let's save registers using Unicorn's context_save?
        # No, we need to push them to GUEST stack so guest can access them if it wants (rarely)
        # and so we can verify integrity.

        # Let's rely on Python-side context saving for restoration?
        # NO. sigreturn is a syscall from GUEST. It must read GUEST stack.

        frame_size = 0x100
        sp -= frame_size

        # Write Magic
        mu.mem_write(sp, b"SIGF")
        # Write PC
        mu.mem_write(sp + 8, int(pc).to_bytes(8, "little"))

        # Restore context is critical. For full correctness we should save all GPRs.
        # But for many lightweight signal handlers (like simple crash handlers), saving PC/LR/SP + arg regs is often "enough" to proceed if they don't corrupt much.
        # Ideally, we would use ucontext_t structure to save everything.
        # For this optimized emulator version, we save minimal context (PC and LR).

        lr_reg = UC_ARM_REG_LR if arch == emu_const.ARCH_ARM32 else UC_ARM64_REG_X30
        lr_val = mu.reg_read(lr_reg)
        mu.mem_write(sp + 16, int(lr_val).to_bytes(8, "little"))

        mu.reg_write(sp_reg, sp)
        mu.reg_write(pc_reg, handler_addr)

        # Set Argument R0/X0 = signal
        if arch == emu_const.ARCH_ARM32:
            mu.reg_write(UC_ARM_REG_R0, signal)
            mu.reg_write(UC_ARM_REG_LR, config.SIGRETURN_TRAMPOLINE_ADDR)
        else:
            mu.reg_write(UC_ARM64_REG_X0, signal)
            mu.reg_write(UC_ARM64_REG_X30, config.SIGRETURN_TRAMPOLINE_ADDR)

        logger.info(
            f"Setup Signal Frame for sig {signal} at sp=0x{sp:x} handler=0x{handler_addr:x}"
        )

    def restore_signal_frame(self, mu):
        arch = self.__emu.get_arch()
        sp_reg = 0
        pc_reg = 0
        if arch == emu_const.ARCH_ARM32:
            sp_reg = UC_ARM_REG_SP
            pc_reg = UC_ARM_REG_PC
        else:
            sp_reg = UC_ARM64_REG_SP
            pc_reg = UC_ARM64_REG_PC

        sp = mu.reg_read(sp_reg)

        # Verify Magic
        magic = mu.mem_read(sp, 4)
        if magic != b"SIGF":
            logger.error("rt_sigreturn: Invalid Magic! Stack corruption likely.")
            # raise Exception("Invalid Signal Frame")

        saved_pc_bytes = mu.mem_read(sp + 8, 8)
        saved_pc = int.from_bytes(saved_pc_bytes, "little")

        saved_lr_bytes = mu.mem_read(sp + 16, 8)
        saved_lr = int.from_bytes(saved_lr_bytes, "little")

        lr_reg = UC_ARM_REG_LR if arch == emu_const.ARCH_ARM32 else UC_ARM64_REG_X30
        mu.reg_write(lr_reg, saved_lr)

        # Restore SP (free frame)
        frame_size = 0x100
        sp += frame_size

        mu.reg_write(sp_reg, sp)
        mu.reg_write(pc_reg, saved_pc)
        logger.info(f"Restored Signal Frame. returning to 0x{saved_pc:x}")

    def _nanosleep(self, mu, req, rem):
        if req != 0:
            req_tv_sec = memory_helpers.read_ptr_sz(mu, req, self.__ptr_sz)
            req_tv_nsec = memory_helpers.read_ptr_sz(
                mu, req + self.__ptr_sz, self.__ptr_sz
            )
            sec = req_tv_sec + (req_tv_nsec / 1e9)
            time.sleep(sec)
        return 0
