from loguru import logger
from unicorn import Uc
from unicorn.arm64_const import (
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X6,
    UC_ARM64_REG_X8,
)
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
)

from ..const import emu_const
from ..scheduler import Scheduler
from .interrupt_handler import InterruptHandler
from .syscall_handler import SyscallHandler


class SyscallHandlers:
    def __init__(self, mu: Uc, schduler: Scheduler, arch: int):
        self._handlers = dict()
        self.__sch = schduler
        self.__interrupt_handler = InterruptHandler(mu)  # 中断处理器
        if arch == emu_const.ARCH_ARM32:
            # arm32 设置系统调用处理函数
            self.__interrupt_handler.set_handler(2, self._handle_syscall)
        else:
            # arm64
            self.__interrupt_handler.set_handler(2, self._handle_syscall64)

    def set_handler(
        self, nr: int, name: str, arg_count: int, callback: callable
    ):
        """设置系统调用处理函数

        Args:
            idx (int): 系统调用号。
            name (str): 系统调用名称。
            arg_count (int): 参数个数。
            callback (callable): 回调函数。
        """
        self._handlers[nr] = SyscallHandler(nr, name, arg_count, callback)

    def _handle_syscall(self, mu: Uc):
        nr = mu.reg_read(UC_ARM_REG_R7)
        lr = mu.reg_read(UC_ARM_REG_LR)
        tid = self.__sch.get_current_tid()
        logger.debug(f"{tid} syscall {nr} lr=0x{lr:08X}")
        args = [
            mu.reg_read(reg_idx)
            for reg_idx in range(UC_ARM_REG_R0, UC_ARM_REG_R6 + 1)
        ]

        args_formatted = ", ".join([f"0x{arg}08X" for arg in args])
        if nr in self._handlers:
            handler = self._handlers[nr]
            args = args[: handler.arg_count]
            logger.debug(
                f"{tid} Executing syscall {handler.name}({args_formatted}) at 0x{mu.reg_read(UC_ARM_REG_PC):08X}"
            )
            try:
                result = handler.callback(mu, *args)
            except:
                logger.exception(
                    f"{tid} An error occured during in {nr} syscall hander, stopping emulation"
                )
                mu.emu_stop()
                raise

            if result is not None:
                mu.reg_write(UC_ARM_REG_R0, result)
        else:
            pc = mu.reg_read(UC_ARM_REG_PC)
            error = f"{tid} Unhandled syscall {nr} at 0x{pc:08X}, args({args_formatted}) stopping emulation"

            logger.exception(error)
            mu.emu_stop()
            raise RuntimeError(error)

    def _handle_syscall64(self, mu):
        idx = mu.reg_read(UC_ARM64_REG_X8)
        lr = mu.reg_read(UC_ARM64_REG_LR)
        tid = self.__sch.get_current_tid()

        logger.debug(f"{tid} syscall {idx} lr=0x{lr:016X}")
        args = [
            mu.reg_read(reg_idx)
            for reg_idx in range(UC_ARM64_REG_X0, UC_ARM64_REG_X6 + 1)
        ]

        if idx in self._handlers:
            handler = self._handlers[idx]
            args = args[: handler.arg_count]
            args_formatted = ", ".join(["0x%08X" % arg for arg in args])
            pc = mu.reg_read(UC_ARM64_REG_PC)
            logger.debug(
                f"{tid} Executing syscall {handler.name}({args_formatted}) at {pc:08X}"
            )
            try:
                result = handler.callback(mu, *args)
            except:
                logger.exception(
                    f"{tid} An error occured during in {idx} syscall hander, stopping emulation"
                )
                mu.emu_stop()
                raise

            if result is not None:
                mu.reg_write(UC_ARM64_REG_X0, result)
        else:
            args_formatted = ", ".join(["0x%016X" % arg for arg in args])
            pc = mu.reg_read(UC_ARM64_REG_PC)
            error = "{tid} Unhandled syscall {idx} at 0x{pc:016X}, args({args_formatted}) stopping emulation"

            logger.exception(error)
            mu.emu_stop()
            raise RuntimeError(error)
