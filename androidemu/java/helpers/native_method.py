from __future__ import annotations

import inspect
import struct
from typing import TYPE_CHECKING, Any, List

from loguru import logger
from unicorn.arm64_const import (
    UC_ARM64_REG_D0,
    UC_ARM64_REG_D1,
    UC_ARM64_REG_D2,
    UC_ARM64_REG_D3,
    UC_ARM64_REG_D4,
    UC_ARM64_REG_D5,
    UC_ARM64_REG_D6,
    UC_ARM64_REG_D7,
    UC_ARM64_REG_S0,
    UC_ARM64_REG_S1,
    UC_ARM64_REG_S2,
    UC_ARM64_REG_S3,
    UC_ARM64_REG_S4,
    UC_ARM64_REG_S5,
    UC_ARM64_REG_S6,
    UC_ARM64_REG_S7,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X5,
    UC_ARM64_REG_X6,
    UC_ARM64_REG_X7,
)
from unicorn.arm_const import (
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_SP,
)

from ...const import emu_const
from ..java_class_def import JavaClassDef
from ..jni_ref import jbyteArray, jclass, jobject, jobjectArray, jstring

if TYPE_CHECKING:
    from ...emulator import Emulator

# ==================== 类型定义 ====================


class Float:
    """强制表示 32 位浮点数 (float)"""

    def __init__(self, value: float):
        self.value = value

    def __repr__(self):
        return f"Float({self.value})"


class Double:
    """强制表示 64 位浮点数 (double)"""

    def __init__(self, value: float):
        self.value = value

    def __repr__(self):
        return f"Double({self.value})"


# ==================== 常量定义 ====================

ARM64_GPR_REGS = [
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X5,
    UC_ARM64_REG_X6,
    UC_ARM64_REG_X7,
]
ARM64_FPR_S_REGS = [
    UC_ARM64_REG_S0,
    UC_ARM64_REG_S1,
    UC_ARM64_REG_S2,
    UC_ARM64_REG_S3,
    UC_ARM64_REG_S4,
    UC_ARM64_REG_S5,
    UC_ARM64_REG_S6,
    UC_ARM64_REG_S7,
]
ARM64_FPR_D_REGS = [
    UC_ARM64_REG_D0,
    UC_ARM64_REG_D1,
    UC_ARM64_REG_D2,
    UC_ARM64_REG_D3,
    UC_ARM64_REG_D4,
    UC_ARM64_REG_D5,
    UC_ARM64_REG_D6,
    UC_ARM64_REG_D7,
]
ARM32_ARG_REGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]

# ==================== 辅助函数 ====================


def float_to_int(val: float) -> int:
    return struct.unpack("<I", struct.pack("<f", val))[0]


def double_to_int(val: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", val))[0]


def int_to_float(val: int) -> float:
    return struct.unpack("<f", val.to_bytes(4, "little"))[0]


def int_to_double(val: int) -> float:
    return struct.unpack("<d", val.to_bytes(8, "little"))[0]


def native_translate_arg(emu: "Emulator", val: Any) -> int:
    """Python 对象转 Native 指针/整数"""
    if isinstance(val, int):
        return val

    jni_env = emu.java_vm.jni_env
    if isinstance(val, str):
        return jni_env.add_local_reference(jstring(val))
    if isinstance(val, (list, tuple)):
        return jni_env.add_local_reference(jobjectArray(val))
    if isinstance(val, (bytes, bytearray)):
        return jni_env.add_local_reference(jbyteArray(val))
    if isinstance(val, JavaClassDef):
        return jni_env.add_local_reference(jclass(val))
    try:
        return jni_env.add_local_reference(jobject(val))
    except Exception:
        return 0  # 无法转换时返回NULL


# ==================== 写入参数 (Call Native) ====================


def native_write_args(emu: "Emulator", *args):
    """写入参数到寄存器和栈，支持浮点和栈对齐"""
    is_arm64 = emu.get_arch() == emu_const.ARCH_ARM64
    mu = emu.mu
    stack_args = []

    if is_arm64:
        gpr_idx = 0
        fpr_idx = 0
        for arg in args:
            is_fp = isinstance(arg, (float, Float, Double))
            if is_fp:
                if fpr_idx < 8:
                    if isinstance(arg, Float):
                        mu.reg_write(ARM64_FPR_S_REGS[fpr_idx], float_to_int(arg.value))
                    else:
                        val = arg.value if isinstance(arg, Double) else arg
                        mu.reg_write(ARM64_FPR_D_REGS[fpr_idx], double_to_int(val))
                    fpr_idx += 1
                else:
                    stack_args.append(arg)
            else:
                if gpr_idx < 8:
                    mu.reg_write(
                        ARM64_GPR_REGS[gpr_idx], native_translate_arg(emu, arg)
                    )
                    gpr_idx += 1
                else:
                    stack_args.append(arg)

        if stack_args:
            _write_stack_arm64(emu, stack_args)
    else:
        # ARM32 简化版 SoftFP
        reg_idx = 0
        for arg in args:
            if isinstance(arg, (float, Double)):
                # Double takes 2 regs
                val = double_to_int(arg.value if isinstance(arg, Double) else arg)
                if reg_idx % 2 != 0:
                    reg_idx += 1  # Align
                if reg_idx + 2 <= 4:
                    mu.reg_write(ARM32_ARG_REGS[reg_idx], val & 0xFFFFFFFF)
                    mu.reg_write(ARM32_ARG_REGS[reg_idx + 1], val >> 32)
                    reg_idx += 2
                else:
                    stack_args.append(arg)
            elif isinstance(arg, Float):
                if reg_idx < 4:
                    mu.reg_write(ARM32_ARG_REGS[reg_idx], float_to_int(arg.value))
                    reg_idx += 1
                else:
                    stack_args.append(arg)
            else:
                if reg_idx < 4:
                    mu.reg_write(
                        ARM32_ARG_REGS[reg_idx], native_translate_arg(emu, arg)
                    )
                    reg_idx += 1
                else:
                    stack_args.append(arg)

        if stack_args:
            _write_stack_arm32(emu, stack_args)


def _write_stack_arm64(emu, args):
    # ARM64 栈必须 16 字节对齐
    sp = emu.mu.reg_read(UC_ARM64_REG_SP)
    data = b""
    for arg in args:
        if isinstance(arg, Float):
            # 扩展到 8 字节
            data += struct.pack("<f", arg.value).ljust(8, b"\x00")
        elif isinstance(arg, (float, Double)):
            val = arg.value if isinstance(arg, Double) else arg
            data += struct.pack("<d", val)
        else:
            data += native_translate_arg(emu, arg).to_bytes(8, "little")

    # Padding
    if len(data) % 16 != 0:
        data += b"\x00" * (16 - (len(data) % 16))

    new_sp = sp - len(data)
    emu.mu.reg_write(UC_ARM64_REG_SP, new_sp)
    emu.mu.mem_write(new_sp, data)


def _write_stack_arm32(emu, args):
    sp = emu.mu.reg_read(UC_ARM_REG_SP)
    data = b""
    for arg in args:
        # 简化处理，不处理复杂的 SoftFP 栈拆分
        val = native_translate_arg(emu, arg)
        if isinstance(arg, Float):
            val = float_to_int(arg.value)
        data += val.to_bytes(4, "little")
    new_sp = sp - len(data)
    emu.mu.reg_write(UC_ARM_REG_SP, new_sp)
    emu.mu.mem_write(new_sp, data)


# ==================== 读取参数 (Hook) ====================


def native_read_args_in_hook(
    emu: "Emulator", params: List[inspect.Parameter]
) -> List[Any]:
    is_arm64 = emu.get_arch() == emu_const.ARCH_ARM64
    mu = emu.mu
    native_args = []

    if is_arm64:
        gpr_idx, fpr_idx = 0, 0
        stack_offset = 0
        sp = mu.reg_read(UC_ARM64_REG_SP)

        for param in params:
            hint = param.annotation
            if hint is float or hint is Double:
                if fpr_idx < 8:
                    val = int_to_double(mu.reg_read(ARM64_FPR_D_REGS[fpr_idx]))
                    native_args.append(val)
                    fpr_idx += 1
                else:
                    # Read double from stack
                    data = mu.mem_read(sp + stack_offset, 8)
                    val = struct.unpack("<d", data)[0]
                    native_args.append(val)
                    stack_offset += 8
            elif hint is Float:
                if fpr_idx < 8:
                    # S reg mapping is complex in Unicorn, read D lower bits
                    val_bits = mu.reg_read(ARM64_FPR_D_REGS[fpr_idx]) & 0xFFFFFFFF
                    native_args.append(int_to_float(val_bits))
                    fpr_idx += 1
                else:
                    # Read float from stack (promoted to 8 bytes or packed? AAPCS64 says natural alignment)
                    # For variadic or unprototyped, promoted to double.
                    # But here we have prototype (hint).
                    # "Each argument... is allocated to the next available stack slot... size of the argument".
                    # However, "each argument... rules... if the argument is a Floating Point... size...".
                    # Usually slots are 8 bytes aligned on stack for simple types in many ABIs, but AAPCS64 allows packing?
                    # "The NSAA is rounded up to the larger of 8 or the Natural Alignment of the argument's type."
                    # So minimum 8 bytes alignment for stack slot? Yes.
                    data = mu.mem_read(sp + stack_offset, 4)  # Read 4 bytes
                    val = struct.unpack("<f", data)[0]
                    # But stack pointer alignment? "NSAA = (NSAA + 7) & ~7" (Align to 8)
                    native_args.append(val)
                    stack_offset += 8  # Consume 8 bytes slot
            else:
                if gpr_idx < 8:
                    native_args.append(mu.reg_read(ARM64_GPR_REGS[gpr_idx]))
                    gpr_idx += 1
                else:
                    val = int.from_bytes(mu.mem_read(sp + stack_offset, 8), "little")
                    native_args.append(val)
                    stack_offset += 8
    else:
        # ARM32 Simple Int Read
        reg_idx = 0
        for param in params:
            if reg_idx < 4:
                native_args.append(mu.reg_read(ARM32_ARG_REGS[reg_idx]))
                reg_idx += 1
            else:
                SP = mu.reg_read(UC_ARM_REG_SP)
                stack_offset = (len(native_args) - 4) * 4
                val = int.from_bytes(mu.mem_read(SP + stack_offset, 4), "little")
                native_args.append(val)

    return native_args


def native_read_args_in_hook_code(emu: "Emulator", nargs: int) -> List[Any]:
    is_arm64 = emu.get_arch() == emu_const.ARCH_ARM64
    mu = emu.mu
    native_args = []

    if is_arm64:
        gpr_idx = 0
        stack_offset = 0
        sp = mu.reg_read(UC_ARM64_REG_SP)
        for _ in range(nargs):
            if gpr_idx < 8:
                native_args.append(mu.reg_read(ARM64_GPR_REGS[gpr_idx]))
                gpr_idx += 1
            else:
                val = int.from_bytes(mu.mem_read(sp + stack_offset, 8), "little")
                native_args.append(val)
                stack_offset += 8
    else:
        # ARM32
        reg_idx = 0
        sp_offset = 0
        for _ in range(nargs):
            if reg_idx < 4:
                native_args.append(mu.reg_read(ARM32_ARG_REGS[reg_idx]))
                reg_idx += 1
            else:
                sp = mu.reg_read(UC_ARM_REG_SP)
                val = int.from_bytes(mu.mem_read(sp + sp_offset, 4), "little")
                native_args.append(val)
                sp_offset += 4

    return native_args


# ==================== 装饰器 ====================


def native_method(func):
    def wrapper(*argv):
        emu = next((arg for arg in argv if hasattr(arg, "mu")), None)
        if not emu:
            raise RuntimeError("Emulator not found in args")
        mu = emu.mu

        sig = inspect.signature(func)
        params = [
            p
            for p in sig.parameters.values()
            if p.name not in ("self", "cls", "mu", "emu", "uc")
        ]

        args = native_read_args_in_hook(emu, params)

        try:
            if len(argv) > 0 and argv[0] != emu:
                res = func(argv[0], mu, *args)
            else:
                res = func(mu, *args)
        except Exception as e:
            logger.exception(f"Hook Error: {func.__name__}")
            raise e

        # Write Return
        if res is not None:
            is_arm64 = emu.get_arch() == emu_const.ARCH_ARM64
            if isinstance(res, (float, Double)):
                if is_arm64:
                    mu.reg_write(
                        UC_ARM64_REG_D0,
                        double_to_int(res if isinstance(res, float) else res.value),
                    )
            elif isinstance(res, Float):
                if is_arm64:
                    mu.reg_write(UC_ARM64_REG_S0, float_to_int(res.value))
            elif isinstance(res, tuple):
                # (r0, r1)
                if is_arm64:
                    mu.reg_write(UC_ARM64_REG_X0, res[0])
                    mu.reg_write(UC_ARM64_REG_X1, res[1])
                else:
                    mu.reg_write(UC_ARM_REG_R0, res[0])
                    mu.reg_write(UC_ARM_REG_R1, res[1])
            else:
                # Int
                if is_arm64:
                    mu.reg_write(UC_ARM64_REG_X0, res)
                else:
                    mu.reg_write(UC_ARM_REG_R0, res)

    return wrapper
