import io
import os

import capstone
from loguru import logger
from unicorn.arm64_const import (
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X5,
    UC_ARM64_REG_X6,
    UC_ARM64_REG_X7,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X9,
    UC_ARM64_REG_X10,
    UC_ARM64_REG_X11,
    UC_ARM64_REG_X12,
    UC_ARM64_REG_X30,
)
from unicorn.arm_const import (
    UC_ARM_REG_CPSR,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_R9,
    UC_ARM_REG_R10,
    UC_ARM_REG_R11,
    UC_ARM_REG_R12,
    UC_ARM_REG_SP,
)

from androidemu.emulator import Emulator

from ..const import emu_const, map_reg


def dump_memory(emu, fd, min_addr=0, max_addr=0xFFFFFFFF):
    mu = emu.mu
    line_connt = 16
    offset = 0
    regions = []
    for r in mu.mem_regions():
        regions.append(r)
    #
    regions.sort()
    for r in regions:
        offset = r[0]
        fd.write("region (0x%08X-0x%08X) prot:%d\n" % (r[0], r[1], r[2]))
        for addr in range(r[0], r[1] + 1):
            if addr < min_addr or addr > max_addr:
                continue

            if offset % line_connt == 0:
                fd.write("0x%08X: " % offset)

            b = mu.mem_read(addr, 1).hex().upper()
            fd.write(" %s" % b)
            offset = offset + 1
            if offset % line_connt == 0:
                fd.write("\n")


def dump_registers(emu, fd):
    regs = ""
    mu = emu.mu
    if emu.get_arch() == emu_const.ARCH_ARM32:
        r0 = mu.reg_read(UC_ARM_REG_R0)
        r1 = mu.reg_read(UC_ARM_REG_R1)
        r2 = mu.reg_read(UC_ARM_REG_R2)
        r3 = mu.reg_read(UC_ARM_REG_R3)
        r4 = mu.reg_read(UC_ARM_REG_R4)
        r5 = mu.reg_read(UC_ARM_REG_R5)
        r6 = mu.reg_read(UC_ARM_REG_R6)
        r7 = mu.reg_read(UC_ARM_REG_R7)
        r8 = mu.reg_read(UC_ARM_REG_R8)
        r9 = mu.reg_read(UC_ARM_REG_R9)
        r10 = mu.reg_read(UC_ARM_REG_R10)
        r11 = mu.reg_read(UC_ARM_REG_R11)
        r12 = mu.reg_read(UC_ARM_REG_R12)
        sp = mu.reg_read(UC_ARM_REG_SP)
        lr = mu.reg_read(UC_ARM_REG_LR)
        pc = mu.reg_read(UC_ARM_REG_PC)
        cpsr = mu.reg_read(UC_ARM_REG_CPSR)
        regs = f"\tR0=0x{r0:08X},R1=0x{r1:08X},R2=0x{r2:08X},R3=0x{r3:08X},R4=0x{r4:08X},R5=0x{r5:08X},R6=0x{r6:08X},R7=0x{r7:08X},\n\tR8=0x{r8:08X},R9=0x{r9:08X},R10=0x{r10:08X},R11=0x{r11:08X},R12=0x{r12:08X}\n\tLR=0x{lr:08X},PC=0x{pc:08X}, SP=0x{sp:08X},CPSR=0x{cpsr:08X}"
    else:
        # arm64
        x0 = mu.reg_read(UC_ARM64_REG_X0)
        x1 = mu.reg_read(UC_ARM64_REG_X1)
        x2 = mu.reg_read(UC_ARM64_REG_X2)
        x3 = mu.reg_read(UC_ARM64_REG_X3)
        x4 = mu.reg_read(UC_ARM64_REG_X4)
        x5 = mu.reg_read(UC_ARM64_REG_X5)
        x6 = mu.reg_read(UC_ARM64_REG_X6)
        x7 = mu.reg_read(UC_ARM64_REG_X7)
        x8 = mu.reg_read(UC_ARM64_REG_X8)
        x9 = mu.reg_read(UC_ARM64_REG_X9)
        x10 = mu.reg_read(UC_ARM64_REG_X10)
        x11 = mu.reg_read(UC_ARM64_REG_X11)
        x12 = mu.reg_read(UC_ARM64_REG_X12)
        sp = mu.reg_read(UC_ARM64_REG_SP)
        x30 = mu.reg_read(UC_ARM64_REG_X30)
        pc = mu.reg_read(UC_ARM64_REG_PC)
        regs = f"\tX0=0x{x0:016X},X1=0x{x1:016X},X2=0x{x2:016X},X3=0x{x3:016X},X4=0x{x4:016X},X5=0x{x5:016X},X6=0x{x6:016X},X7=0x{x7:016X},\n\tX8=0x{x8:016X},X9=0x{x9:016X},X10=0x{x10:016X},X11=0x{x11:016X},X12=0x{x12:016X}\n\tLR=0x{x30:016X},PC=0x{pc:016X}, SP=0x{sp:016X}"

    fd.write(regs + "\n")


def dump_symbols(emulator, fd):
    for m in emulator.modules:
        for addr in m.symbol_lookup:
            v = m.symbol_lookup[addr]
            fd.write("0x%08X(0x%08X):%s\n" % (addr, addr - m.base, v[0]))


g_md_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
g_md_thumb.detail = True

g_md_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
g_md_arm.detail = True

g_md_arm64 = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
g_md_arm64.detail = True


def get_module_by_addr(emu: Emulator, addr: int):
    ms = emu.modules
    module = None
    for m in ms:
        if addr >= m.base and addr <= m.base + m.size:
            module = m
            break
    return module


# print code and its moudle in a line
DUMP_REG_READ = 1
DUMP_REG_WRITE = 2


def dump_code(
    emu: Emulator, address: int, size: int, fd: int, dump_reg_type=DUMP_REG_READ
):
    mu = emu.mu
    uc_regs = map_reg.arm_reg_map
    if emu.get_arch() == emu_const.ARCH_ARM32:
        # 判断是否 arm，用不同的 decoder
        cpsr = mu.reg_read(UC_ARM_REG_CPSR)
        if cpsr & (1 << 5):
            md = g_md_thumb
        else:
            md = g_md_arm
    else:
        # arm64
        md = g_md_arm64
        uc_regs = map_reg.arm64_reg_map

    instruction = mu.mem_read(address, size)
    codes = md.disasm(instruction, address)

    for i in codes:
        addr = i.address

        name = "unknown"
        module = None
        base = 0
        funName = None
        module = get_module_by_addr(emu, addr)
        if module is not None:
            name = os.path.basename(module.filename)
            base = module.base
            funName = module.is_symbol_addr(addr)

        instruction_str = "".join("{:02X} ".format(x) for x in i.bytes)
        tid = ""
        if emu.get_muti_task_support():
            sch = emu.get_schduler()
            tid = f"{sch.get_current_tid()}:"
        line = f"{tid}({name}[0x{base:08X}])[0x{addr - base:08X}]:\t{instruction_str}\t{i.mnemonic.upper()} {i.op_str.upper()}"
        if funName is not None:
            line = line + f" ; {funName}"

        regs = i.regs_access()
        if DUMP_REG_READ == dump_reg_type:
            regs_dump = regs[0]
        elif DUMP_REG_WRITE == dump_reg_type:
            regs_dump = regs[1]

        regs_io = io.StringIO()
        for rid in regs_dump:
            reg_name = i.reg_name(rid).lower()
            reg_index = uc_regs.get(reg_name, -1)
            if reg_index == -1:
                logger.warning(f"unknown register {reg_name}.")
                continue
            reg_value = mu.reg_read(reg_index)
            reg_str = f"{reg_name}=0x{reg_value:08X} "
            regs_io.write(reg_str)

        regs = regs_io.getvalue()
        if regs != "":
            line = f"{line}\t;({regs})"

        fd.write(line + "\n")


def dump_stack(emu: Emulator, fd, max_deep=512):
    mu = emu.mu
    sp = 0
    if emu.get_arch() == emu_const.ARCH_ARM32:
        sp = mu.reg_read(UC_ARM_REG_SP)
    else:
        sp = mu.reg_read(UC_ARM64_REG_SP)
    stop = sp + max_deep
    fd.wirte("stack dumps:\n")
    ptr_sz = emu.get_ptr_size()
    for ptr in range(sp, stop, ptr_sz):
        valb = mu.mem_read(ptr, ptr_sz)
        val = int.from_bytes(valb, byteorder="little", signed=False)
        line = f"0x{ptr:08X}: 0x{val:08X}\n"
        fd.write(line)
