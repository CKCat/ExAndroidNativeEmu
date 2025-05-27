import importlib
import inspect
import os
import os.path
import pkgutil
import sys

from loguru import logger
from unicorn import (
    UC_ARCH_ARM,
    UC_ARCH_ARM64,
    UC_MODE_ARM,
    UC_PROT_EXEC,
    UC_PROT_READ,
    UC_PROT_WRITE,
    Uc,
)
from unicorn.arm64_const import (
    UC_ARM64_REG_CPACR_EL1,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
)
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP

from . import config, pcb
from .const import emu_const
from .cpu.syscall_handlers import SyscallHandlers
from .cpu.syscall_hooks import SyscallHooks
from .hooker import Hooker
from .internal.modules import Modules
from .java.helpers.native_method import native_write_args
from .java.java_class_def import JavaClassDef
from .java.java_classloader import JavaClassLoader
from .java.java_vm import JavaVM
from .native.memory_map import MemoryMap
from .native.memory_syscall_handler import MemorySyscallHandler
from .native.symbol_hooks import SymbolHooks
from .scheduler import Scheduler
from .utils import misc_utils
from .vfs.file_system import VirtualFileSystem
from .vfs.virtual_file import VirtualFile


class Emulator:
    # https://github.com/unicorn-engine/unicorn/blob/8c6cbe3f3cabed57b23b721c29f937dd5baafc90/tests/regress/arm_fp_vfp_disabled.py#L15
    # 关于arm32 64 fp https://www.raspberrypi.org/forums/viewtopic.php?t=259802
    # https://www.cnblogs.com/pengdonglin137/p/3727583.html
    def __enable_vfp32(self):
        # MRC p15, #0, r1, c1, c0, #2
        # ORR r1, r1, #(0xf << 20)
        # MCR p15, #0, r1, c1, c0, #2
        # MOV r1, #0
        # MCR p15, #0, r1, c7, c5, #4
        # MOV r0,#0x40000000
        # FMXR FPEXC, r0
        code = "11EE501F"
        code += "41F47001"
        code += "01EE501F"
        code += "4FF00001"
        code += "07EE951F"
        code += "4FF08040"
        code += "E8EE100A"
        # vpush {d8}
        code += "2ded028b"

        address = 0x1000
        mem_size = 0x1000
        code_bytes = bytes.fromhex(code)

        try:
            self.mu.mem_map(address, mem_size)
            self.mu.mem_write(address, code_bytes)
            self.mu.reg_write(UC_ARM_REG_SP, address + mem_size)

            self.mu.emu_start(address | 1, address + len(code_bytes))
        finally:
            self.mu.mem_unmap(address, mem_size)

    def __enable_vfp64(self):
        # arm64 enable vfp
        # arm64
        """
        mrs    x1, cpacr_el1
        mov    x0, #(3 << 20)
        orr    x0, x1, x0
        msr    cpacr_el1, x0
        """
        x = 0
        x = self.mu.reg_read(UC_ARM64_REG_CPACR_EL1)
        x |= 0x300000  # set FPEN bit
        self.mu.reg_write(UC_ARM64_REG_CPACR_EL1, x)

    def __add_classes(self):
        # 当前文件路径
        cur_file_dir = os.path.dirname(__file__)
        # 运行的脚本文件路径
        entry_file_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        # python 约定 package_name 总是相对于入口脚本目录
        package_name = os.path.relpath(cur_file_dir, entry_file_dir).replace(
            "/", "."
        )
        logger.debug(package_name)
        full_dirname = f"{cur_file_dir}/java/classes"

        # 加载所有的 java 类
        preload_classes = set()
        for importer, mod_name, c in pkgutil.iter_modules([full_dirname]):
            import_name = f".java.classes.{mod_name}"
            # 导入 classes 模块
            m = importlib.import_module(import_name, package_name)
            # 获取所有的 java 类
            clsList = inspect.getmembers(m, inspect.isclass)
            for name, clz in clsList:
                if type(clz) == JavaClassDef:
                    preload_classes.add(clz)

        for clz in preload_classes:
            self.java_classloader.add_class(clz)

        # also add classloader as java class
        self.java_classloader.add_class(JavaClassLoader)

    def __init__(
        self,
        vfs_root: str = "vfs",
        config_path: str = "emu_cfg/default.json",
        vfp_inst_set: bool = True,
        arch: int = emu_const.ARCH_ARM32,
        muti_task: bool = False,
    ):
        # 由于这里的 stream 只能改一次，为避免与 fork 之后的子进程写到 stdout 混合，将这些 log 写到 stderr
        # FIXME:解除这种特殊的依赖
        sys.stdout = sys.stderr
        self.config = config.Config(config_path)
        # 架构
        self.__arch = arch
        # 是否支持多线程任务
        self.__support_muti_task = muti_task
        # 进程控制块信息
        self.__pcb = pcb.Pcb()

        logger.info(f"process pid: {self.__pcb.get_pid()}")

        sp_reg = 0
        if arch == emu_const.ARCH_ARM32:
            # ARM 模式
            self.__ptr_sz = 4
            self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            if vfp_inst_set:
                self.__enable_vfp32()

            sp_reg = UC_ARM_REG_SP
            self.call_native = self.__call_native32
            self.call_native_return_2reg = self.__call_native_return_2reg32

        elif arch == emu_const.ARCH_ARM64:
            # ARM64 模式
            self.__ptr_sz = 8
            self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            if vfp_inst_set:
                self.__enable_vfp64()

            sp_reg = UC_ARM64_REG_SP

            self.call_native = self.__call_native64
            self.call_native_return_2reg = self.__call_native_return_2reg64

        else:
            raise RuntimeError(f"emulator arch={arch} not support!!!")
        # 虚拟文件系统根目录
        self.__vfs_root = vfs_root

        # 注意，原有缺陷，原来 linker 初始化没有完成 init_tls 部分，导致 libc 初始化有访问空指针而无法正常完成
        # 而这里直接将0映射空间，,强行运行过去，因为R1刚好为0,否则会报memory unmap异常
        # 最新版本已经解决这个问题，无需再这么映射
        # self.mu.mem_map(0x0, 0x00001000, UC_PROT_READ | UC_PROT_WRITE)

        # Android 4.4
        if arch == emu_const.ARCH_ARM32:
            self.system_properties = {
                "libc.debug.malloc.options": "",
                "ro.build.version.sdk": "19",
                "ro.build.version.release": "4.4.4",
                "persist.sys.dalvik.vm.lib": "libdvm.so",
                "ro.product.cpu.abi": "armeabi-v7a",
                "ro.product.cpu.abi2": "armeabi",
                "ro.product.manufacturer": "LGE",
                "ro.debuggable": "0",
                "ro.product.model": "AOSP on HammerHead",
                "ro.hardware": "hammerhead",
                "ro.product.board": "hammerhead",
                "ro.product.device": "hammerhead",
                "ro.build.host": "833d1eed3ea3",
                "ro.build.type": "user",
                "ro.secure": "1",
                "wifi.interface": "wlan0",
                "ro.product.brand": "Android",
            }
        #
        else:
            # FIXME 这里arm64用 6.0，应该arm32也统一使用6.0
            # Android 6.0
            self.system_properties = {
                "libc.debug.malloc.options": "",
                "ro.build.version.sdk": "23",
                "ro.build.version.release": "6.0.1",
                "persist.sys.dalvik.vm.lib2": "libart.so",
                "ro.product.cpu.abi": "arm64-v8a",
                "ro.product.manufacturer": "LGE",
                "ro.debuggable": "0",
                "ro.product.model": "AOSP on HammerHead",
                "ro.hardware": "hammerhead",
                "ro.product.board": "hammerhead",
                "ro.product.device": "hammerhead",
                "ro.build.host": "833d1eed3ea3",
                "ro.build.type": "user",
                "ro.secure": "1",
                "wifi.interface": "wlan0",
                "ro.product.brand": "Android",
            }

        # 内存映射
        self.memory = MemoryMap(
            self.mu,
            config.MAP_ALLOC_BASE,
            config.MAP_ALLOC_BASE + config.MAP_ALLOC_SIZE,
        )
        logger.debug(
            f"memory map base: 0x{config.MAP_ALLOC_BASE:08X}, size: 0x{config.MAP_ALLOC_SIZE:08X}"
        )
        # 栈
        self.memory.map(
            config.STACK_ADDR, config.STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE
        )
        logger.debug(
            f"stack addr: 0x{config.STACK_ADDR:08X}, size: 0x{config.STACK_SIZE:08X}"
        )
        self.mu.reg_write(sp_reg, config.STACK_ADDR + config.STACK_SIZE)

        self.__sch = Scheduler(self)
        # CPU
        self.__syscall_handler = SyscallHandlers(
            self.mu, self.__sch, self.get_arch()
        )

        # Hooker
        self.memory.map(
            config.BRIDGE_MEMORY_BASE,
            config.BRIDGE_MEMORY_SIZE,
            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
        )
        self.__hooker = Hooker(
            self, config.BRIDGE_MEMORY_BASE, config.BRIDGE_MEMORY_SIZE
        )

        # syscalls
        self.__mem_handler = MemorySyscallHandler(
            self, self.memory, self.__syscall_handler
        )
        self.__syscall_hooks = SyscallHooks(
            self, self.config, self.__syscall_handler
        )
        self.__vfs = VirtualFileSystem(
            self, vfs_root, self.config, self.__syscall_handler, self.memory
        )

        # JavaVM
        self.java_classloader = JavaClassLoader()
        self.java_vm = JavaVM(self, self.java_classloader, self.__hooker)

        # linker
        self.modules = Modules(self, self.__vfs_root)
        # Native
        self.__sym_hooks = SymbolHooks(
            self, self.modules, self.__hooker, self.__vfs_root
        )

        self.__add_classes()

        # Hack 为 jmethod_id 指向的内存分配一块空间，抖音会将jmethodID强转，为的是绕过去
        self.memory.map(
            config.JMETHOD_ID_BASE,
            0x2000,
            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
        )

        if arch == emu_const.ARCH_ARM32:
            # 映射常用的文件，cpu一些原子操作的函数实现地方
            path = f"{vfs_root}/system/lib/vectors"
            vf = VirtualFile(
                "[vectors]", misc_utils.my_open(path, os.O_RDONLY), path
            )
            self.memory.map(
                0xFFFF0000, 0x1000, UC_PROT_EXEC | UC_PROT_READ, vf, 0
            )

            # 映射 app_process，android 系统基本特征
            path = f"{vfs_root}/system/bin/app_process32"
            sz = os.path.getsize(path)
            vf = VirtualFile(
                "/system/bin/app_process32",
                misc_utils.my_open(path, os.O_RDONLY),
                path,
            )
            self.memory.map(0xAB006000, sz, UC_PROT_EXEC | UC_PROT_READ, vf, 0)

        else:
            # 映射app_process，android系统基本特征
            path = f"{vfs_root}/system/bin/app_process64"
            sz = os.path.getsize(path)
            vf = VirtualFile(
                "/system/bin/app_process64",
                misc_utils.my_open(path, os.O_RDONLY),
                path,
            )
            self.memory.map(0xAB006000, sz, UC_PROT_EXEC | UC_PROT_READ, vf, 0)

    def get_vfs_root(self):
        return self.__vfs_root

    def load_library(self, filename: str, do_init: bool = True):
        libmod = self.modules.load_module(filename, do_init)
        return libmod

    def call_symbol(self, module, symbol_name: str, *argv):
        symbol_addr = module.find_symbol(symbol_name)

        if symbol_addr is None:
            logger.error(
                "Unable to find symbol '%s' in module '%s'."
                % (symbol_name, module.filename)
            )
            return

        return self.call_native(symbol_addr, *argv)

    def __call_native32(self, addr: int, *argv):
        assert addr is not None, (
            "call addr is None, make sure your jni native function has registered by RegisterNative!"
        )
        native_write_args(self, *argv)
        self.__sch.exec(addr)
        # Read result from locals if jni.
        res = self.mu.reg_read(UC_ARM_REG_R0)
        return res

    def __call_native64(self, addr, *argv):
        assert addr is not None, (
            "call addr is None, make sure your jni native function has registered by RegisterNative!"
        )
        native_write_args(self, *argv)
        self.__sch.exec(addr)
        # Read result from locals if jni.
        res = self.mu.reg_read(UC_ARM64_REG_X0)
        return res

    # 返回值8个字节,用两个寄存器保存
    def __call_native_return_2reg32(self, addr, *argv):
        res = self.__call_native32(addr, *argv)

        res_high = self.mu.reg_read(UC_ARM_REG_R1)

        return (res_high << 32) | res

    # 返回值16个字节,用两个寄存器保存
    def __call_native_return_2reg64(self, addr, *argv):
        res = self.__call_native64(addr, *argv)

        res_high = self.mu.reg_read(UC_ARM64_REG_X1)

        return (res_high << 64) | res

    def get_arch(self):
        return self.__arch

    def get_ptr_size(self):
        return self.__ptr_sz

    def get_pcb(self):
        return self.__pcb

    def get_schduler(self):
        return self.__sch

    def get_muti_task_support(self):
        return self.__support_muti_task
