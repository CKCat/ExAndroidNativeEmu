import posixpath
import sys

from loguru import logger
from unicorn import (
    UcError,
)
from unicorn.arm_const import UC_ARM_REG_PC

from androidemu.const import emu_const
from androidemu.emulator import Emulator
from androidemu.java.classes.array import ByteArray
from androidemu.utils.chain_log import ChainLogger

g_cfd = ChainLogger(sys.stderr, "./ins-jni.txt")


if __name__ == "__main__":
    # 初始化emulator
    emulator = Emulator(
        vfs_root=posixpath.join(
            posixpath.dirname(__file__),
            "vfs",
        ),
        arch=emu_const.ARCH_ARM64,
    )

    logger.debug("Loaded vfs.")
    # Load all libraries.
    lib_module = emulator.load_library("tests/bin64/libvoida2dfae4581f5.so")

    # androidemu.utils.debug_utils.dump_symbols(emulator, sys.stdout)

    # Show loaded modules.
    logger.info("Loaded modules:")

    for module in emulator.modules:
        logger.info("=> 0x%08x - %s" % (module.base, module.filename))

    try:
        # Do native stuff.
        with open("tests/bin64/out", "rb") as f:
            data = f.read()

        result = emulator.call_symbol(
            lib_module,
            "Java_com_android_apn_common_strings_ededb9cd18a9_ba2dfae4581f5",
            emulator.java_vm.jni_env.address_ptr,
            0,
            ByteArray(data),
        )
        retult = emulator.java_vm.jni_env.get_local_reference(result)
        logger.info(f"resutl: {retult.value.get_py_items().decode('utf8')}")

        # Dump natives found.
        logger.info("Exited EMU.")
        logger.info("Native methods registered to MainActivity:")

    except UcError:
        print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
        raise
