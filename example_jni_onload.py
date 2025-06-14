import posixpath
import sys

from loguru import logger
from unicorn import (
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_PROT_EXEC,
    UcError,
)
from unicorn.arm64_const import UC_ARM64_REG_X3
from unicorn.arm_const import UC_ARM_REG_PC

import androidemu.utils.debug_utils
from androidemu.const import emu_const
from androidemu.emulator import Emulator
from androidemu.java.classes.string import String
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.utils.chain_log import ChainLogger

g_cfd = ChainLogger(sys.stderr, "./ins-jni.txt")


# Add debugging.
def hook_code(mu, address, size, user_data):
    try:
        emu = user_data
        x3 = emu.mu.reg_read(UC_ARM64_REG_X3)
        if x3 == 0x100FD590:
            logger.debug(f"0x{address:08X} UC_ARM64_REG_X3 == 0x100FD590")
        if not emu.memory.check_addr(address, UC_PROT_EXEC):
            logger.error("addr 0x%08X out of range" % (address,))
            sys.exit(-1)
        #
        # androidemu.utils.debug_utils.dump_registers(mu, sys.stdout)
        androidemu.utils.debug_utils.dump_code(emu, address, size, g_cfd)
    except Exception:
        logger.exception("exception in hook_code")
        sys.exit(-1)


def hook_mem_read(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)

    if address == 0x100FD590:
        logger.debug("read mutex")
        data = uc.mem_read(address, size)
        v = int.from_bytes(data, byteorder="little", signed=False)
        logger.warning(
            ">>> Memory READ at 0x%08X, data size = %u,  data value = 0x%08X, pc: 0x%08X,"
            % (address, size, v, pc)
        )


def hook_mem_write(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    if address == 0x100FD590:
        logger.warning("write mutex")
        logger.warning(
            ">>> Memory WRITE at 0x%08X, data size = %u, data value = 0x%08X, pc: 0x%08X"
            % (address, size, value, pc)
        )


class MainActivity(
    metaclass=JavaClassDef, jvm_name="org/ckcat/uniron/MainActivity"
):
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
    def base64(self, *args, **argv):
        print(f"{args} {argv}")
        # content = base64.b64encode(args[0].value)
        return String("hello base64")


if __name__ == "__main__":
    # 初始化emulator
    emulator = Emulator(
        vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs"),
        arch=emu_const.ARCH_ARM64,
    )

    logger.debug("Loaded vfs.")
    # 注册 MainActivity 类
    emulator.java_classloader.add_class(MainActivity)
    emulator.java_classloader.add_class(Encrypt)
    emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)

    emulator.mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
    emulator.mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)

    logger.info("Register native methods.")
    # Load all libraries.
    lib_module = emulator.load_library("tests/bin64/libuniron.so")

    # androidemu.utils.debug_utils.dump_symbols(emulator, sys.stdout)

    # Show loaded modules.
    logger.info("Loaded modules:")

    for module in emulator.modules:
        logger.info("=> 0x%08x - %s" % (module.base, module.filename))

    try:
        # Run JNI_OnLoad.
        # JNI_OnLoad will call 'RegisterNatives'.
        emulator.call_symbol(
            lib_module, "JNI_OnLoad", emulator.java_vm.address_ptr, 0x00
        )
        main_activity = MainActivity()
        retult = main_activity.sayHello(
            emulator,
            String("Hello ExAndroidNativeEmu"),
        )
        logger.info(f"resutl: {retult}")
        # 通过偏移调用
        retult = emulator.call_native(
            lib_module.base + 0xB54,
            emulator.java_vm.jni_env.address_ptr,
            0x00,
            String("Hello ExAndroidNativeEmu"),
        )
        retult = emulator.java_vm.jni_env.get_local_reference(retult)
        logger.info(f"resutl: {retult.value}")

        # Dump natives found.
        logger.info("Exited EMU.")
        logger.info("Native methods registered to MainActivity:")

    except UcError:
        print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
        raise
