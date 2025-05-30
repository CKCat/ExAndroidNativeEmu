from unicorn.arm64_const import UC_ARM64_REG_SP
from unicorn.arm_const import UC_ARM_REG_SP

from ..const import emu_const
from . import memory_helpers


class StackHelper:
    def __init__(self, emu):
        self.__emu = emu
        arch = emu.get_arch()
        if arch == emu_const.ARCH_ARM32:
            self.pointersize = 4
            sp_reg = UC_ARM_REG_SP
        elif arch == emu_const.ARCH_ARM64:
            self.pointersize = 8
            sp_reg = UC_ARM64_REG_SP
        sp = emu.mu.reg_read(sp_reg)
        self.__sp = sp
        self.__sp_reg = sp_reg

    def reserve(self, nptr):
        self.__sp -= nptr * self.__emu.get_ptr_size()
        return self.__sp

    def write_val(self, value):
        ptr_sz = self.__emu.get_ptr_size()
        self.__sp -= ptr_sz
        memory_helpers.write_ptrs_sz(self.__emu.mu, self.__sp, value, ptr_sz)
        return self.__sp

    def write_utf8(self, str_val):
        value_utf8 = str_val.encode(encoding="utf-8") + b"\x00"
        n = len(value_utf8)
        self.__sp -= n
        self.__emu.mu.mem_write(self.__sp, value_utf8)
        return self.__sp

    def commit(self):
        # 对齐sp
        if self.__emu.get_arch() == emu_const.ARCH_ARM32:
            self.__sp = self.__sp & (~7)
        elif self.__emu.get_arch() == emu_const.ARCH_ARM64:
            self.__sp = self.__sp & (~15)

        self.__emu.mu.reg_write(self.__sp_reg, self.__sp)

    def stack_push(self, value: int) -> int:
        self.__sp -= self.pointersize
        self.__emu.mu.mem_write(
            self.__sp,
            value,
        )

        return self.regs.arch_sp

    def stack_pop(self) -> int:
        data = self.ql.mem.read_ptr(self.regs.arch_sp)
        self.__sp += self.pointersize

        return data

    def get_sp(self):
        return self.__sp
