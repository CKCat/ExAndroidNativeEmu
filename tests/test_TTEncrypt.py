import logging
import sys
import struct
import hexdump  # 如果没有请 pip install hexdump，或者使用自定义函数
from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.java.classes.array import ByteArray
from androidemu.java.jni_ref import jobject
from unicorn import *
from unicorn.arm_const import *


# 1. 定义 Java 类
class TTEncryptUtils(
    metaclass=JavaClassDef,
    jvm_name="com/bytedance/frameworks/core/encrypt/TTEncryptUtils",
):
    def __init__(self):
        pass

    # 对应: public static native byte[] ttEncrypt(byte[] bArr, int i);
    @java_method_def(name="ttEncrypt", signature="([BI)[B", native=True)
    def ttEncrypt(self, mu):
        pass


# 辅助函数：简单的 Hex Dump
def print_hex(name, data):
    print(f"[{name}] len={len(data)}")
    if len(data) > 0:
        hexdump.hexdump(data)


# 全局变量用于存储 postCall 需要的上下文（简化处理）
call_context = {}

# 2. Hook 回调函数定义


# 模拟 HookZz.wrap(ss_encrypt)
def hook_ss_encrypt_pre(mu, address, size, user_data):
    # 读取参数: R0, R1, R2, R3
    # ss_encrypt 可能是 (ctx, input, key, key_len) 这种形式，根据 Java 代码推断
    # Java 代码: key = pointer.getByteArray(0, length); (arg2 is pointer, arg3 is int)
    r2_ptr = mu.reg_read(UC_ARM_REG_R2)
    r3_len = mu.reg_read(UC_ARM_REG_R3)

    if r3_len > 0 and r3_len < 1024:
        key_data = mu.mem_read(r2_ptr, r3_len)
        print_hex("ss_encrypt key", key_data)

    # 记录 LR (返回地址) 以便模拟 postCall
    lr = mu.reg_read(UC_ARM_REG_LR)
    call_context["ss_encrypt_lr"] = lr


# 模拟 ss_encrypted_size 的 Replace Hook
def hook_ss_encrypted_size(mu, address, size, user_data):
    # Java: System.out.println("ss_encrypted_size.onCall arg0=" + context.getIntArg(0)...
    arg0 = mu.reg_read(UC_ARM_REG_R0)
    print(f"ss_encrypted_size.onCall arg0={arg0}, originFunction=0x{address:x}")
    # 这里我们只是打印，如果要 HookStatus.RET，可以直接修改 PC 到 LR
    # mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_LR))


# 模拟 XHook: strlen
def hook_strlen(mu, address, size, user_data):
    r0_ptr = mu.reg_read(UC_ARM_REG_R0)
    try:
        # 读取字符串，简单读取直到 \0
        s_bytes = b""
        for i in range(100):
            b = mu.mem_read(r0_ptr + i, 1)
            if b == b"\x00":
                break
            s_bytes += b
        print(f"strlen arg='{s_bytes.decode('utf-8', 'ignore')}'")
    except:
        pass


# 模拟 XHook: memmove
def hook_memmove(mu, address, size, user_data):
    dest = mu.reg_read(UC_ARM_REG_R0)
    src = mu.reg_read(UC_ARM_REG_R1)
    length = mu.reg_read(UC_ARM_REG_R2)

    if length > 0 and length < 4096:
        try:
            data = mu.mem_read(src, length)
            print_hex(f"memmove dest=0x{dest:x}", data)
        except:
            pass


def main():
    # 初始化模拟器
    emulator = Emulator(vfp_inst_set=True)

    # 加载基础库
    emulator.load_library("libc.so")
    emulator.load_library("libstdc++.so")
    emulator.load_library("libm.so")
    emulator.load_library("libdl.so")

    # 注册 Java 类
    emulator.java_classloader.add_class(TTEncryptUtils)

    # 加载目标 SO
    # 注意：确保 libttEncrypt.so 和依赖都在 vfs 路径下
    try:
        lib_module = emulator.load_library("tests/bin/libttEncrypt.so")
    except Exception as e:
        print(f"Error loading library: {e}")
        return

    # 获取基地址
    base_addr = lib_module.base
    print(f"Library loaded at 0x{base_addr:x}")

    # ================= 3. 还原 Unidbg 的 Inspector / Hook 逻辑 =================

    # 3.1 查找符号 sbox0, sbox1 并打印
    sbox0_addr = lib_module.find_symbol("sbox0")
    sbox1_addr = lib_module.find_symbol("sbox1")

    if sbox0_addr:
        sbox0_data = emulator.mu.mem_read(sbox0_addr, 256)
        print_hex("sbox0", sbox0_data)

    if sbox1_addr:
        sbox1_data = emulator.mu.mem_read(sbox1_addr, 256)
        print_hex("sbox1", sbox1_data)

    # 3.2 模拟 HookZz wrap (ss_encrypt)
    ss_encrypt_addr = lib_module.find_symbol("ss_encrypt")
    if ss_encrypt_addr:
        print(f"Hooking ss_encrypt at 0x{ss_encrypt_addr:x}")
        # 在函数入口添加 Hook
        emulator.mu.hook_add(
            UC_HOOK_CODE,
            hook_ss_encrypt_pre,
            begin=ss_encrypt_addr,
            end=ss_encrypt_addr,
        )

    # 3.3 模拟 HookZz instrument (inline hook at offset)
    # Java: module.base + 0x00000F5C + 1
    # 注意：Unicorn Hook 地址必须是偶数（Thumb 模式下自动处理，但地址最好对齐）
    # 如果是 Thumb 指令，地址 +1；Hook 时传入实际地址(去除+1)并将模式设为 Thumb
    # 这里简单假设在 0xF5C 处 Hook
    target_offset = 0xF5C
    target_addr = base_addr + target_offset

    def hook_instrument(mu, address, size, user_data):
        # R3 和 R10
        r3 = mu.reg_read(UC_ARM_REG_R3)
        r10 = mu.reg_read(UC_ARM_REG_R10)
        print(f"[Instrument] R3={r3}, R10=0x{r10:x}")

    emulator.mu.hook_add(
        UC_HOOK_CODE, hook_instrument, begin=target_addr, end=target_addr
    )

    # 3.4 模拟 Dobby replace (ss_encrypted_size)
    ss_size_addr = lib_module.find_symbol("ss_encrypted_size")
    if ss_size_addr:
        emulator.mu.hook_add(
            UC_HOOK_CODE, hook_ss_encrypted_size, begin=ss_size_addr, end=ss_size_addr
        )

    # 3.5 模拟 XHook (Hook 导入函数)
    # 在 AndroidNativeEmu 中，通常直接 Hook libc 中的导出函数即可覆盖所有调用
    # 除非你想只 Hook libttEncrypt.so 对 libc 的调用 (那需要解析 PLT/GOT)
    # 这里为了简单，直接 Hook libc 的函数地址
    libc = emulator.modules.find_module("libc.so")
    if libc:
        strlen_addr = libc.find_symbol("strlen")
        memmove_addr = libc.find_symbol("memmove")
        memcpy_addr = libc.find_symbol("memcpy")

        if strlen_addr:
            emulator.mu.hook_add(
                UC_HOOK_CODE, hook_strlen, begin=strlen_addr, end=strlen_addr
            )

        if memmove_addr:
            emulator.mu.hook_add(
                UC_HOOK_CODE, hook_memmove, begin=memmove_addr, end=memmove_addr
            )

        # memcpy 和 memmove 逻辑类似，复用回调
        if memcpy_addr:
            emulator.mu.hook_add(
                UC_HOOK_CODE, hook_memmove, begin=memcpy_addr, end=memcpy_addr
            )

    # ================= 4. 执行 JNI 方法 =================

    print("\nExecuting JNI method ttEncrypt...")

    # 准备参数
    data = bytearray(16)  # new byte[16]
    data_len = len(data)

    # 构造 JNI 参数
    # native 方法签名: ([BI)[B
    # 参数 1: byte[]
    # 参数 2: int

    # 将 python bytearray 转换为 JNI jbyteArray
    jbyte_array = emulator.java_vm.jni_env.add_local_reference(
        jobject(ByteArray(list(data)))
    )

    # 查找 Native 函数地址
    # 方式 A: 静态导出 Java_com_bytedance_frameworks_core_encrypt_TTEncryptUtils_ttEncrypt
    symbol_name = "Java_com_bytedance_frameworks_core_encrypt_TTEncryptUtils_ttEncrypt"
    func_addr = lib_module.find_symbol(symbol_name)

    # 方式 B: 动态注册 (JNI_OnLoad)
    # 如果 find_symbol 失败，则从 ClassDef 中查找 (假设 JNI_OnLoad 已运行)
    if not func_addr:
        # 手动调用 JNI_OnLoad (AndroidNativeEmu 通常在 load_library 时尝试调用，但有时需要手动)
        # JNI_OnLoad = lib_module.find_symbol("JNI_OnLoad")
        # emulator.call_native(JNI_OnLoad, ...)

        # 查找注册后的地址
        for method in emulator.java_classloader.find_class_by_name(
            "com/bytedance/frameworks/core/encrypt/TTEncryptUtils"
        ).jvm_methods.values():
            if method.name == "ttEncrypt":
                func_addr = method.native_addr
                break

    if not func_addr:
        print("Error: Native function address not found.")
        return

    # 调用 Native 函数
    # JNI Env 和 jclass/jobject 由 call_native 辅助处理或手动传
    # static 方法: (JNIEnv*, jclass, jbyteArray, jint)

    # 获取 JNIEnv 指针
    jni_env_ptr = emulator.java_vm.jni_env.address_ptr
    # 获取 jclass 指针 (任意非0值即可，或者真实 ID)
    jclass_ptr = 0x8888

    result_ptr = emulator.call_native(
        func_addr, jni_env_ptr, jclass_ptr, jbyte_array, data_len
    )

    # 处理返回值
    if result_ptr:
        # result_ptr 是一个 jobject (jbyteArray)
        # 从 JNI 引用表中取出对象
        res_obj = emulator.java_vm.jni_env.get_local_reference(result_ptr)
        if res_obj:
            print_hex("ttEncrypt Result", res_obj.value)
        else:
            print("Result object is None")
    else:
        print("Native call returned 0 (NULL)")


if __name__ == "__main__":
    main()
