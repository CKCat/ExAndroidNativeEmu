from loguru import logger
from unicorn import Uc
from unicorn.arm64_const import (
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X5,
    UC_ARM64_REG_X8,
)
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
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
        self.__interrupt_handler = InterruptHandler(mu)
        self.__arch = arch

        # 定义系统调用参数寄存器列表，Linux syscall 最多 6 个参数
        if arch == emu_const.ARCH_ARM32:
            self._arg_regs = [
                UC_ARM_REG_R0,
                UC_ARM_REG_R1,
                UC_ARM_REG_R2,
                UC_ARM_REG_R3,
                UC_ARM_REG_R4,
                UC_ARM_REG_R5,
            ]
            # ARM32 通过中断 2 (SWI/SVC) 触发系统调用
            self.__interrupt_handler.set_handler(2, self._handle_syscall)
        else:
            self._arg_regs = [
                UC_ARM64_REG_X0,
                UC_ARM64_REG_X1,
                UC_ARM64_REG_X2,
                UC_ARM64_REG_X3,
                UC_ARM64_REG_X4,
                UC_ARM64_REG_X5,
            ]
            # ARM64 也是通过中断 2 (SVC) 触发
            self.__interrupt_handler.set_handler(2, self._handle_syscall64)

    def set_handler(
        self, nr: int, name: str, arg_count: int, callback: callable
    ):
        """设置系统调用处理函数"""
        self._handlers[nr] = SyscallHandler(nr, name, arg_count, callback)

    def _handle_syscall(self, mu: Uc):
        # ARM32: R7 存放系统调用号
        nr = mu.reg_read(UC_ARM_REG_R7)
        lr = mu.reg_read(UC_ARM_REG_LR)
        tid = self.__sch.get_current_tid()

        # 读取参数
        args = [mu.reg_read(reg) for reg in self._arg_regs]

        if nr in self._handlers:
            handler = self._handlers[nr]
            # 截取实际需要的参数
            call_args = args[: handler.arg_count]

            # 修复格式化字符串错误: {arg:08X}
            args_formatted = ", ".join([f"0x{arg:08X}" for arg in call_args])
            pc = mu.reg_read(UC_ARM_REG_PC)

            logger.debug(
                f"[{tid}] Syscall {handler.name}({args_formatted}) "
                f"NR={nr} at 0x{pc:08X} lr=0x{lr:08X}"
            )

            try:
                result = handler.callback(mu, *call_args)
            except Exception as e:
                logger.exception(
                    f"[{tid}] Exception in syscall handler {handler.name} ({nr})"
                )
                mu.emu_stop()
                raise e

            if result is not None:
                # 处理负数返回值 (例如 -1 转为 0xFFFFFFFF)
                if result < 0:
                    result = result & 0xFFFFFFFF
                mu.reg_write(UC_ARM_REG_R0, result)
        else:
            pc = mu.reg_read(UC_ARM_REG_PC)
            # 打印全部6个可能的参数，方便调试未知调用
            args_formatted = ", ".join([f"0x{arg:08X}" for arg in args])
            error = (
                f"[{tid}] Unhandled syscall NR={nr} at 0x{pc:08X}, "
                f"args=({args_formatted}) stopping emulation"
            )
            logger.error(error)
            mu.emu_stop()
            raise RuntimeError(error)

    def _handle_syscall64(self, mu: Uc):
        # ARM64: X8 存放系统调用号
        nr = mu.reg_read(UC_ARM64_REG_X8)
        lr = mu.reg_read(UC_ARM64_REG_LR)
        tid = self.__sch.get_current_tid()

        args = [mu.reg_read(reg) for reg in self._arg_regs]

        if nr in self._handlers:
            handler = self._handlers[nr]
            call_args = args[: handler.arg_count]

            args_formatted = ", ".join([f"0x{arg:016X}" for arg in call_args])
            pc = mu.reg_read(UC_ARM64_REG_PC)

            logger.debug(
                f"[{tid}] Syscall {handler.name}({args_formatted}) "
                f"NR={nr} at 0x{pc:016X} lr=0x{lr:016X}"
            )

            try:
                result = handler.callback(mu, *call_args)
            except Exception as e:
                logger.exception(
                    f"[{tid}] Exception in syscall handler {handler.name} ({nr})"
                )
                mu.emu_stop()
                raise e

            if result is not None:
                # 修复：处理负数返回值 (ARM64转为64位无符号)
                if result < 0:
                    result = result & 0xFFFFFFFFFFFFFFFF
                mu.reg_write(UC_ARM64_REG_X0, result)
        else:
            pc = mu.reg_read(UC_ARM64_REG_PC)
            args_formatted = ", ".join([f"0x{arg:016X}" for arg in args])
            error = (
                f"[{tid}] Unhandled syscall NR={nr} at 0x{pc:016X}, "
                f"args=({args_formatted}) stopping emulation"
            )
            logger.error(error)
            mu.emu_stop()
            raise RuntimeError(error)
