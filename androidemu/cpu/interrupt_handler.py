import traceback
from typing import Any, Callable, Dict

from loguru import logger
from unicorn import UC_ARCH_ARM, UC_ARCH_ARM64, UC_HOOK_INTR, Uc
from unicorn.arm64_const import UC_ARM64_REG_PC
from unicorn.arm_const import UC_ARM_REG_PC


class InterruptHandler:
    def __init__(self, mu: Uc):
        self._mu = mu
        self._handlers: Dict[int, Callable[[Uc], None]] = dict()

        # 缓存架构信息，避免每次中断都查询 (性能优化 + 兼容性)
        # 注意：这里假设 mu 已经被正确初始化架构，通常通过内部属性判断
        # 如果 Unicorn 版本差异大，建议在 __init__ 中显式传入 arch 参数
        self._arch = (
            self._mu._arch if hasattr(self._mu, "_arch") else UC_ARCH_ARM
        )

        # 注册中断钩子
        self._mu.hook_add(UC_HOOK_INTR, self._hook_interrupt)

    def _get_pc(self) -> int:
        """根据架构安全地获取 PC 指针"""
        if self._arch == UC_ARCH_ARM:
            return self._mu.reg_read(UC_ARM_REG_PC)
        elif self._arch == UC_ARCH_ARM64:
            return self._mu.reg_read(UC_ARM64_REG_PC)
        return 0

    def _hook_interrupt(self, uc: Uc, intno: int, user_data: Any):
        """
        Unicorn 中断回调
        :param intno: 中断号 (例如 ARM32 下 SVC 0 通常触发中断 2)
        """
        try:
            if intno in self._handlers:
                # 调用注册的处理函数 (通常是 SyscallHandlers._handle_syscall)
                self._handlers[intno](uc)
            else:
                pc = self._get_pc()

                # 修复格式化字符串错误
                error_msg = (
                    f"Unhandled interrupt intno={intno} (0x{intno:X}) "
                    f"at PC=0x{pc:08X}, stopping emulation."
                )
                logger.error(error_msg)

                # 打印 Python 调用栈，方便调试模拟器本身的逻辑错误
                traceback.print_stack()

                self._mu.emu_stop()
                raise RuntimeError(error_msg)

        except Exception as e:
            # 捕获处理逻辑中的异常，防止模拟器崩溃时无日志
            logger.exception(
                f"Exception occurred in _hook_interrupt intno:[{intno}]"
            )
            # 停止模拟
            self._mu.emu_stop()
            # 必须抛出异常对象，不能抛出字符串
            raise RuntimeError(f"Interrupt handler failure: {e}") from e

    def set_handler(self, intno: int, handler: Callable[[Uc], None]):
        """
        注册中断处理函数
        :param intno: 中断号
        :param handler: 回调函数，接收 Uc 实例
        """
        self._handlers[intno] = handler
        logger.debug(f"Registered interrupt handler for intno {intno}")
