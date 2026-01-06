import sys
import unittest

from loguru import logger
from unicorn import UC_PROT_EXEC, UcError
from unicorn.arm_const import UC_ARM_REG_PC

import androidemu.utils.debug_utils
from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.utils.chain_log import ChainLogger

g_cfd = ChainLogger(sys.stderr, "./ins-jni.txt")


# ================= 调试 Hook =================
def hook_code(mu, address, size, user_data):
    try:
        emu = user_data
        if not emu.memory.check_addr(address, UC_PROT_EXEC):
            logger.error("地址 0x%08X 超出范围" % (address,))
            sys.exit(-1)
        #
        # androidemu.utils.debug_utils.dump_registers(mu, sys.stdout)
        androidemu.utils.debug_utils.dump_code(emu, address, size, g_cfd)
    except Exception:
        logger.exception("exception in hook_code")
        sys.exit(-1)


def hook_mem_read(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)

    # 监控特定地址 (调试用)
    if address == 0xCBC80640:
        logger.debug("读取互斥锁")
        data = uc.mem_read(address, size)
        v = int.from_bytes(data, byteorder="little", signed=False)
        logger.debug(
            ">>> 内存读取 at 0x%08X, 大小 = %u, 值 = 0x%08X, pc: 0x%08X,"
            % (address, size, v, pc)
        )


def hook_mem_write(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    if address == 0xCBC80640:
        logger.debug("写入互斥锁")
        logger.debug(
            ">>> 内存写入 at 0x%08X, 大小 = %u, 值 = 0x%08X, pc: 0x%08X"
            % (address, size, value, pc)
        )


# ================= Java 类定义 =================
class MainActivity(
    metaclass=JavaClassDef, jvm_name="local/myapp/testnativeapp/MainActivity"
):
    def __init__(self):
        pass

    @java_method_def(
        name="stringFromJNI", signature="()Ljava/lang/String;", native=True
    )
    def string_from_jni(self, mu):
        pass

    def test(self):
        pass


class TestExampleJNI(unittest.TestCase):
    def test_string_from_jni(self):
        logger.info("=== 测试 JNI 调用 ===")

        # 1. 初始化模拟器
        emulator = Emulator(vfs_root="androidemu/data/vfs", vfp_inst_set=True)
        logger.debug("VFS 加载完成.")

        # 2. 注册 Java 类
        emulator.java_classloader.add_class(MainActivity)

        # 3. 添加 Hook (可选，调试用)
        # emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)
        # emulator.mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
        # emulator.mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)

        logger.debug("正在加载目标库...")
        # 4. 加载 SO 库 (需确保依赖库如 libc 等也被加载，或者测试用例环境简单可忽略)
        # 在这里我们假设 .so 依赖已经满足，或者它不需要其他库
        # 为了健壮性，通常先加载 libc
        emulator.load_library("libc.so")
        emulator.load_library("libdl.so")
        # emulator.load_library("liblog.so")

        lib_module = emulator.load_library("tests/bin/libnative-lib_jni.so")

        # 显示加载的模块
        logger.info("已加载模块:")
        for module in emulator.modules:
            logger.info("=> 0x%08x - %s" % (module.base, module.filename))

        try:
            # 5. 执行 JNI_OnLoad
            # JNI_OnLoad 将调用 RegisterNatives
            emulator.call_symbol(
                lib_module, "JNI_OnLoad", emulator.java_vm.address_ptr, 0x00
            )

            # 6. 调用 Native 方法
            # 通过 Python 代理对象调用
            main_activity = MainActivity()
            result_obj = main_activity.string_from_jni(emulator)

            # 检查结果
            if result_obj:
                result = result_obj.get_py_string()
                logger.info("JNI 调用返回: %s" % result)
                self.assertEqual(result, "Hello from C++ ONLOAD!!")
            else:
                logger.error("Return value is None")
                self.fail("JNI call returned None")

            logger.info("测试结束.")

        except UcError:
            print("崩溃地址: %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
            raise


if __name__ == "__main__":
    unittest.main()
