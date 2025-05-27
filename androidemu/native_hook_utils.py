import traceback

from loguru import logger
from unicorn import UC_HOOK_CODE, UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE
from unicorn.arm64_const import (
    UC_ARM64_REG_PC,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X30,
)
from unicorn.arm_const import (
    UC_ARM_REG_CPSR,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
)

from .const import emu_const
from .java.helpers.native_method import native_read_args_in_hook_code


def is_thumb(cpsr):
    return (cpsr & (1 << 5)) != 0


def set_thumb(cpsr):
    return cpsr | (1 << 5)


def clear_thumb(cpsr):
    return cpsr & (~(1 << 5))


def standlize_addr(addr):
    return addr & (~1)


# 函数hook
class FuncHooker:
    # 32 layout
    """
    funAddr
    ldr lr, [pc, #0x0]
    bx lr
    original lr
    """

    # 64 layout
    """
    funcAddr
    #ldr x30, #0x8
    #br x30
    original lr
    """

    def __hook_stub(self, mu, address, size, user_data):
        try:
            address = standlize_addr(address)
            fun_entry_addr = address - self.__emu.get_ptr_size()
            fun_entry_bytes = mu.mem_read(
                fun_entry_addr, self.__emu.get_ptr_size()
            )
            fun_entry = int.from_bytes(
                fun_entry_bytes, byteorder="little", signed=False
            )
            if fun_entry in self.__hook_params:
                hook_param = self.__hook_params[fun_entry]
                cb_after = hook_param[2]
                r0 = 0
                r1 = 0
                if self.__arch == emu_const.ARCH_ARM32:
                    r0 = mu.reg_read(UC_ARM_REG_R0)
                    r1 = mu.reg_read(UC_ARM_REG_R1)

                else:
                    r0 = mu.reg_read(UC_ARM64_REG_X0)
                    r1 = mu.reg_read(UC_ARM64_REG_X1)

                cb_after(self.__emu, r0, r1)

        except Exception:
            # Make sure we catch exceptions inside hooks and stop emulation.
            mu.emu_stop()
            traceback.print_exc()
            logger.exception("catch error on _hook")
            raise "catch error on _hook"

    def __init__(self, emu):
        self.__emu = emu
        self.__arch = self.__emu.get_arch()
        self.__hook_params = {}
        HOOK_STUB_MEMORY_SIZE = 0x00100000
        self.__stub_off = self.__emu.memory.map(
            0,
            HOOK_STUB_MEMORY_SIZE,
            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
        )
        self.__emu.mu.hook_add(
            UC_HOOK_CODE,
            self.__hook_stub,
            None,
            self.__stub_off,
            self.__stub_off + HOOK_STUB_MEMORY_SIZE,
        )

    def __hook_func_head(self, mu, address, size, user_data):
        try:
            address = standlize_addr(address)
            if address not in self.__hook_params:
                return

            logger.debug("trigger hook on 0x%08X" % address)
            hook_param = self.__hook_params[address]
            nargs = hook_param[0]
            args = native_read_args_in_hook_code(self.__emu, nargs)
            if hook_param[1]:
                is_handled = hook_param[1](self.__emu, *args)
                if is_handled:
                    # 如果逻辑已经被处理，则直接返回
                    if self.__arch == emu_const.ARCH_ARM32:
                        cpsr = mu.reg_read(UC_ARM_REG_CPSR)
                        lr = self.__emu.reg_read(UC_ARM_REG_LR)
                        # same as BX LR
                        if lr & 1:
                            # thumb set TF
                            cpsr = set_thumb(cpsr)
                        else:
                            # arm clear TF
                            cpsr = clear_thumb(cpsr)
                        mu.reg_write(UC_ARM_REG_CPSR, cpsr)
                        mu.reg_write(UC_ARM_REG_PC, lr)
                    else:
                        lr = self.__emu.reg_read(UC_ARM64_REG_X30)
                        mu.reg_write(UC_ARM64_REG_PC, lr)
                    return

            if hook_param[2]:
                # 因为不知道最后一条指令是什么，需要只能改变返回的地址，再hook从而达到 callback after的效果
                # 改变lr，返回到跳板，
                if self.__arch == emu_const.ARCH_ARM32:
                    mu.mem_write(
                        self.__stub_off,
                        address.to_bytes(4, byteorder="little", signed=False),
                    )  # 写入函数地址
                    self.__stub_off += 4

                    new_lr = self.__stub_off
                    # 跳板跳回原返回地址
                    mu.mem_write(
                        self.__stub_off, b"\x00\xe0\x9f\xe5"
                    )  # ldr lr, [pc, #0x0]
                    self.__stub_off += 4
                    mu.mem_write(self.__stub_off, b"\x1e\xff\x2f\xe1")  # bx lr
                    self.__stub_off += 4
                    lr = mu.reg_read(UC_ARM_REG_LR)
                    mu.mem_write(
                        self.__stub_off,
                        lr.to_bytes(4, byteorder="little", signed=False),
                    )  # 备份返回地址
                    self.__stub_off += 4
                    mu.reg_write(UC_ARM_REG_LR, new_lr)
                else:
                    mu.mem_write(
                        self.__stub_off,
                        address.to_bytes(8, byteorder="little", signed=False),
                    )  # 写入函数地址
                    self.__stub_off += 8

                    new_lr = self.__stub_off
                    mu.mem_write(
                        self.__stub_off, b"\x5e\x00\x00\x58"
                    )  # ldr x30, #0x8
                    self.__stub_off += 4
                    mu.mem_write(self.__stub_off, b"\xc0\x03\x1f\xd6")  # br x30
                    self.__stub_off += 4

                    lr = mu.reg_read(UC_ARM64_REG_X30)
                    mu.mem_write(
                        self.__stub_off,
                        lr.to_bytes(8, byteorder="little", signed=False),
                    )  # 备份返回地址
                    self.__stub_off += 8
                    mu.reg_write(UC_ARM64_REG_X30, new_lr)

        except Exception:
            # Make sure we catch exceptions inside hooks and stop emulation.
            mu.emu_stop()
            traceback.print_exc()
            logger.exception("catch error on _hook")
            raise "catch error on _hook"

    def fun_hook(self, fun_addr, nargs, cb_before, cb_after):
        fun_addr = standlize_addr(fun_addr)
        mu = self.__emu.mu
        mu.hook_add(
            UC_HOOK_CODE, self.__hook_func_head, None, fun_addr, fun_addr + 4
        )
        self.__hook_params[fun_addr] = (nargs, cb_before, cb_after)
