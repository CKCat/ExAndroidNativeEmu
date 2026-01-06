import base64
import sys
import unittest

import capstone
import unicorn
from loguru import logger
from unicorn import UcError
from unicorn.arm64_const import UC_ARM64_REG_X3
from unicorn.arm_const import UC_ARM_REG_PC

from androidemu.const import emu_const
from androidemu.emulator import Emulator
from androidemu.java.classes.string import String
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.utils.chain_log import ChainLogger

g_cfd = ChainLogger(sys.stderr, "./ins-jni.txt")


def print_arm64_regs(mu):
    regs = ["X0", "X1", "X2", "X3", "X29", "SP"]
    count = 0
    output = ""
    for reg in regs:
        val = mu.reg_read(getattr(unicorn.arm64_const, f"UC_ARM64_REG_{reg}"))
        if count < 8:
            output += f"{reg} = 0x{val:x}\t"
            count += 1
        else:
            output += f"\n{reg} = 0x{val:x}\t"
            count = 0
    print(output)


# ================= 调试 Hook =================
def hook_code(mu, address, size, user_data):
    try:
        # 调试指定范围内的指令
        if 0xCBBCBC8C <= address <= 0xCBBCBD6C:
            print_arm64_regs(mu)
            code = mu.mem_read(address, size)
            CP = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            for i in CP.disasm(code, 0, size):
                print(f"0x{address:08X}: {i.mnemonic}: {i.op_str}")

            # 手动分析某些特定逻辑 (示例)
            if address == 0xCBBCBD48:
                x3 = mu.reg_read(UC_ARM64_REG_X3)
                data = mu.mem_read(x3, 8)
                logger.debug(
                    f"0x{x3:08X}: __stack: {int.from_bytes(data, 'little'):08X}"
                )
    except Exception as e:
        logger.error(e)


def hook_mem_read(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)

    if address == 0x100FD590:
        logger.debug("读取互斥锁")
        data = uc.mem_read(address, size)
        v = int.from_bytes(data, byteorder="little", signed=False)
        logger.warning(
            ">>> 内存读取 at 0x%08X, 大小 = %u, 值 = 0x%08X, pc: 0x%08X,"
            % (address, size, v, pc)
        )


def hook_mem_write(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    if address == 0x100FD590:
        logger.warning("写入互斥锁")
        logger.warning(
            ">>> 内存写入 at 0x%08X, 大小 = %u, 值 = 0x%08X, pc: 0x%08X"
            % (address, size, value, pc)
        )


# ================= Java 类定义 =================
class MainActivity(metaclass=JavaClassDef, jvm_name="org/ckcat/uniron/MainActivity"):
    def __init__(self):
        pass

    @java_method_def(
        name="sayHello",
        signature="(Ljava/lang/String;)Ljava/lang/String;",
        native=True,
    )
    def sayHello(self, mu, content):
        pass


class Encrypt(metaclass=JavaClassDef, jvm_name="org/ckcat/uniron/Encrypt"):
    def __init__(self):
        pass

    @java_method_def(
        name="base64",
        signature="(Ljava/lang/String;)Ljava/lang/String;",
        native=False,
        args_list=["jstring"],
    )
    def base64(emu, jstr):
        # Python 实现的 Java 方法，供 Native 调用
        # 注意: 静态方法被调用时，第一个参数是 emulator 实例
        print(f"Java 方法被调用: Encrypt.base64({jstr})")
        str_content = jstr.get_py_string()
        print(f"原始内容: {str_content}")

        # Base64 编码
        content = base64.b64encode(str_content.encode("utf8"))
        result = content.decode("utf8")
        print(f"编码结果: {result}")

        return String(result)


# ================= 主测试逻辑 =================
class TestUnironJNI(unittest.TestCase):
    def test_say_hello(self):
        logger.info("=== 测试 Uniron JNI (ARM64) ===")

        # 1. 初始化模拟器 (ARM64)
        emulator = Emulator(
            vfs_root="androidemu/data/vfs",
            arch=emu_const.ARCH_ARM64,
        )
        logger.debug("VFS 加载完成.")

        # 2. 注册 Java 类
        emulator.java_classloader.add_class(MainActivity)
        emulator.java_classloader.add_class(Encrypt)

        # 调试 Hook (可选)
        # emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)
        # emulator.mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
        # emulator.mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)

        logger.info("加载 64位 系统库...")
        try:
            # 确保加载基础库
            emulator.load_library("libc.so")
            # emulator.load_library("liblog.so") # 视情况加载
        except Exception as e:
            logger.warning("系统库加载部分跳过或失败: %s" % e)

        # 3. 加载目标库
        lib_module = emulator.load_library("tests/bin64/libuniron.so")

        # 显示加载的模块
        logger.info("已加载模块:")
        for module in emulator.modules:
            logger.info("=> 0x%08x - %s" % (module.base, module.filename))

        try:
            # 4. 执行 JNI_OnLoad
            logger.info("执行 JNI_OnLoad ...")
            emulator.call_symbol(
                lib_module, "JNI_OnLoad", emulator.java_vm.address_ptr, 0x00
            )

            # 5. 调用 Native 方法
            main_activity = MainActivity()
            input_str = "Hello ExAndroidNativeEmu"
            logger.info(f"调用 sayHello('{input_str}')...")

            result = main_activity.sayHello(
                emulator,
                String(input_str),
            )

            result_str = None
            if hasattr(result, "get_py_string"):
                result_str = result.get_py_string()
            else:
                result_str = str(result)

            logger.info(f"JNI 返回结果: {result_str}")
            self.assertIsNotNone(result)

            logger.info("测试结束.")

        except UcError:
            print("崩溃地址: %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
            raise


if __name__ == "__main__":
    unittest.main()
