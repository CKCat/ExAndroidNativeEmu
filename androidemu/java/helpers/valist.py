import ctypes

from loguru import logger
from unicorn import Uc


# AArch64 的 __gnuc_va_list 结构
# AAPCS64 定义
# gr_offs: 从 __gr_top 到下一个 GP 寄存器参数的偏移量
# vr_offs: 从 __vr_top 到下一个 FP/SIMD 寄存器参数的偏移量
class VaListAArch64(ctypes.Structure):
    _fields_ = [
        ("__stack", ctypes.c_uint64),
        ("__gr_top", ctypes.c_uint64),
        ("__vr_top", ctypes.c_uint64),
        ("__gr_offs", ctypes.c_int32),
        ("__vr_offs", ctypes.c_int32),
    ]


def get_next_int_arg64(uc: "Uc", va_list_addr: int) -> int:
    """
    模拟 ARM64 AAPCS64 的 va_arg(ap, int/long/pointer)。
    """
    try:
        data = uc.mem_read(va_list_addr, 32)  # sizeof(VaListAArch64)
        va_list = VaListAArch64.from_buffer_copy(data)

        val = 0
        # 检查参数是否在通用寄存器保存区中
        # gr_offs 从 -64 到 0。如果 >= 0，则寄存器已用完。
        if va_list.__gr_offs >= 0:
            # 从栈中获取
            addr = va_list.__stack
            val = int.from_bytes(uc.mem_read(addr, 8), "little")
            va_list.__stack += 8
        else:
            # 从寄存器保存区获取
            # Address = gr_top + gr_offs
            addr = va_list.__gr_top + va_list.__gr_offs
            val = int.from_bytes(uc.mem_read(addr, 8), "little")
            va_list.__gr_offs += 8  # 移动到下一个寄存器

        # 写回修改后的状态
        uc.mem_write(va_list_addr, bytes(va_list))
        return val
    except Exception as e:
        logger.error(f"解析位于 0x{va_list_addr:X} 的 ARM64 va_list 时出错: {e}")
        return 0


def get_next_float_arg64(uc: "Uc", va_list_addr: int, is_double: bool = False) -> float:
    """
    模拟 ARM64 AAPCS64 的 va_arg(ap, double/float)。
    """
    try:
        data = uc.mem_read(va_list_addr, 32)
        va_list = VaListAArch64.from_buffer_copy(data)

        import struct

        val_bytes = b""

        if va_list.__vr_offs >= 0:
            # 栈 (Stack)
            # 根据 AAPCS64，参数在栈上是 8 字节对齐的
            addr = va_list.__stack
            val_raw = uc.mem_read(addr, 8)
            va_list.__stack += 8

            if is_double:
                val_bytes = val_raw
            else:
                val_bytes = val_raw[:4]
        else:
            # 寄存器保存区 (Register Save Area)
            # 每个槽位是 16 字节 (128-bit)
            addr = va_list.__vr_top + va_list.__vr_offs
            # 我们只需要读取前 8/4 字节 (Little Endian)
            val_raw = uc.mem_read(addr, 8)

            # VR 偏移总是前进 16 字节
            va_list.__vr_offs += 16

            if is_double:
                val_bytes = val_raw
            else:
                val_bytes = val_raw[:4]

        # 写回修改后的状态
        uc.mem_write(va_list_addr, bytes(va_list))

        fmt = "<d" if is_double else "<f"
        return struct.unpack(fmt, val_bytes)[0]

    except Exception as e:
        logger.error(
            f"解析位于 0x{va_list_addr:X} 的 ARM64 va_list (float) 时出错: {e}"
        )
        return 0.0
