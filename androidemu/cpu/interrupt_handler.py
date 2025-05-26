import inspect
import sys
import traceback

from loguru import logger
from unicorn import UC_ARCH_ARM, UC_ARCH_ARM64, UC_HOOK_INTR, UC_QUERY_ARCH, Uc
from unicorn.arm64_const import UC_ARM64_REG_PC
from unicorn.arm_const import UC_ARM_REG_PC


class InterruptHandler:
    def __init__(self, mu: Uc):
        self._mu = mu
        # 注册中断处理函数
        self._mu.hook_add(UC_HOOK_INTR, self._hook_interrupt)
        self._handlers = dict()

    def _hook_interrupt(self, uc: Uc, intno: int, user_data):
        try:
            if intno in self._handlers:
                # 直接调用中断处理函数
                self._handlers[intno](uc)
            else:
                pc = 0
                arch = self._mu.query(UC_QUERY_ARCH)
                if arch == UC_ARCH_ARM:
                    pc = self._mu.reg_read(UC_ARM_REG_PC)
                elif arch == UC_ARCH_ARM64:
                    pc = self._mu.reg_read(UC_ARM64_REG_PC)

                logger.error(
                    f"Unhandled interrupt {intno} at %x, stopping emulation {pc}"
                )
                traceback.print_stack()
                frame = inspect.currentframe()
                stack_trace = traceback.format_stack(frame)
                logger.error("catch error on _hook_interrupt")
                logger.error(stack_trace[:-1])
                self._mu.emu_stop()
                sys.exit(-1)
        except Exception:
            logger.exception(f"exception in _hook_interrupt intno:[{intno}]")
            sys.exit(-1)

    def set_handler(self, intno: int, handler: callable):
        self._handlers[intno] = handler
