from __future__ import annotations

import inspect
from typing import TYPE_CHECKING

from unicorn.arm64_const import (
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
)
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP

from ...const import emu_const
from ..java_class_def import JavaClassDef
from ..jni_ref import jbyteArray, jclass, jobject, jobjectArray, jstring

if TYPE_CHECKING:
    from ...emulator import Emulator


def native_write_args(emu: "Emulator", *args):
    """设置函数的参数

    Args:
        emu (Emulator): 模拟器。
    """
    max_regs_args = 4
    reg_base = UC_ARM_REG_R0
    sp_reg = UC_ARM_REG_SP

    if emu.get_arch() == emu_const.ARCH_ARM64:
        max_regs_args = 8
        reg_base = UC_ARM64_REG_X0
        sp_reg = UC_ARM64_REG_SP

    ptr_sz = emu.get_ptr_size()

    # 如果参数的个数小于等于4，直接写入寄存器
    amount = len(args)
    nreg = max_regs_args
    if amount < max_regs_args:
        nreg = amount

    for i in range(0, nreg):
        native_write_arg_register(emu, reg_base + i, args[i])

    # 使用栈传递参数
    if amount > max_regs_args:
        sp_start = emu.mu.reg_read(sp_reg)
        sp_current = sp_start
        sp_current = sp_current - (
            ptr_sz * (amount - max_regs_args)
        )  # Reserve space for arguments.
        sp_end = sp_current

        for arg in args[max_regs_args:]:
            emu.mu.mem_write(
                sp_current,
                native_translate_arg(emu, arg).to_bytes(
                    ptr_sz, byteorder="little"
                ),
            )
            sp_current = sp_current + ptr_sz

        emu.mu.reg_write(sp_reg, sp_end)


def native_read_args_in_hook_code(emu: "Emulator", args_count: int):
    max_regs_args = 4  # 寄存器参数个数
    reg_base = UC_ARM_REG_R0
    sp_reg = UC_ARM_REG_SP

    if emu.get_arch() == emu_const.ARCH_ARM64:
        max_regs_args = 8
        reg_base = UC_ARM64_REG_X0
        sp_reg = UC_ARM64_REG_SP

    ptr_sz = emu.get_ptr_size()

    nreg = max_regs_args
    if args_count < max_regs_args:
        nreg = args_count

    native_args = []
    mu = emu.mu

    for i in range(0, nreg):
        native_args.append(mu.reg_read(reg_base + i))

    if args_count > max_regs_args:
        sp = mu.reg_read(sp_reg)

        for x in range(0, args_count - max_regs_args):
            native_args.append(
                int.from_bytes(
                    mu.mem_read(sp + (x * ptr_sz), ptr_sz), byteorder="little"
                )
            )
    return native_args


def native_translate_arg(emu: "Emulator", val):
    if isinstance(val, int):
        return val
    elif isinstance(val, str):
        return emu.java_vm.jni_env.add_local_reference(jstring(val))
    elif isinstance(val, list):
        return emu.java_vm.jni_env.add_local_reference(jobjectArray(val))
    elif isinstance(val, bytearray):
        return emu.java_vm.jni_env.add_local_reference(jbyteArray(val))
    elif isinstance(type(val), JavaClassDef):
        # TODO: Look into this, seems wrong..
        return emu.java_vm.jni_env.add_local_reference(jobject(val))
    elif isinstance(val, JavaClassDef):
        return emu.java_vm.jni_env.add_local_reference(jclass(val))
    else:
        raise NotImplementedError(
            "Unable to write response '%s' type '%s' to emulator."
            % (str(val), type(val))
        )


def native_write_arg_register(emu: "Emulator", reg: int, val):
    emu.mu.reg_write(reg, native_translate_arg(emu, val))


# 定义 native 层回调到 python 的方法
def native_method(func):
    def native_method_wrapper(*argv):
        """
        :type self
        :type emu androidemu.emulator.Emulator
        :type mu Uc
        """

        emu = argv[1] if len(argv) == 2 else argv[0]
        mu = emu.mu
        # 判断参数个数
        args = inspect.getfullargspec(func).args
        args_count = len(args) - (2 if "self" in args else 1)

        if args_count < 0:
            raise RuntimeError(
                "NativeMethod accept at least (self, mu) or (mu)."
            )

        native_args = native_read_args_in_hook_code(emu, args_count)

        if len(argv) == 1:  # 从寄存器取参数
            result = func(mu, *native_args)
        else:
            le = len(native_args)
            result = func(argv[0], mu, *native_args)

        ret_reg0 = UC_ARM_REG_R0
        ret_reg1 = UC_ARM_REG_R1
        if emu.get_arch() == emu_const.ARCH_ARM64:
            ret_reg0 = UC_ARM64_REG_X0
            ret_reg1 = UC_ARM64_REG_X1

        if result is not None:
            if isinstance(result, tuple):
                # tuple 作为特殊返回8字节数据约定
                rlow = result[0]
                rhigh = result[1]
                native_write_arg_register(emu, ret_reg0, rlow)
                native_write_arg_register(emu, ret_reg1, rhigh)
            else:
                # FIXME handle python基本类型str int float,处理返回值逻辑略为混乱，
                # 返回值的问题统一在这里处理掉
                native_write_arg_register(emu, ret_reg0, result)

    return native_method_wrapper
