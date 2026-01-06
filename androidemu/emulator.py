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

from . import config
from .internal import pcb
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
    def __enable_vfp32(self):
        # 启用 ARM32 VFP (Vector Floating Point)
        # 代码来自 Unicorn regression tests
        code = "11EE501F"  # mrc p15, 0, r1, c1, c0, 2
        code += "41F47001"  # orr r1, r1, #0xf00000
        code += "01EE501F"  # mcr p15, 0, r1, c1, c0, 2
        code += "4FF00001"  # mov r1, #0
        code += "07EE951F"  # mcr p15, 0, r1, c7, c5, 4 (ISB)
        code += "4FF08040"  # mov r0, #0x40000000
        code += "E8EE100A"  # fmxr fpexc, r0
        # code += "2ded028b" # vpush {d8} - 移除这条测试指令，避免栈操作副作用

        address = 0x1000
        mem_size = 0x1000
        code_bytes = bytes.fromhex(code)

        try:
            self.mu.mem_map(address, mem_size, UC_PROT_READ | UC_PROT_EXEC)
            self.mu.mem_write(address, code_bytes)

            # 保存当前 PC 和 SP，避免启用 VFP 破坏上下文（虽然通常在初始化时调用）
            self.mu.reg_write(UC_ARM_REG_SP, address + mem_size)

            self.mu.emu_start(address | 1, address + len(code_bytes))
        finally:
            self.mu.mem_unmap(address, mem_size)

    def __enable_vfp64(self):
        """
        Enable ARM64 FP access (CPACR_EL1)
        mrs    x1, cpacr_el1
        mov    x0, #(3 << 20)
        orr    x0, x1, x0
        msr    cpacr_el1, x0
        """
        # 0x300000 = (3 << 20), 设置 FPEN 位，允许 EL0/EL1 访问浮点单元
        x = self.mu.reg_read(UC_ARM64_REG_CPACR_EL1)
        x |= 0x300000
        self.mu.reg_write(UC_ARM64_REG_CPACR_EL1, x)

    def __add_classes(self):
        """自动加载 ./java/classes 目录下的所有 Java 类定义"""
        cur_file_dir = os.path.dirname(__file__)
        entry_file_dir = os.path.dirname(os.path.realpath(sys.argv[0]))

        # 计算 package name 用于 importlib
        if entry_file_dir in cur_file_dir:
            package_name = os.path.relpath(cur_file_dir, entry_file_dir).replace(
                os.path.sep, "."
            )
        else:
            # Fallback: 假设 androidemu 是根包
            package_name = "androidemu"

        logger.debug(f"Loading classes from package: {package_name}")
        full_dirname = os.path.join(cur_file_dir, "java", "classes")

        preload_classes = {}

        # 遍历目录加载模块
        for importer, mod_name, c in pkgutil.iter_modules([full_dirname]):
            import_name = f".java.classes.{mod_name}"
            try:
                # 尝试相对导入，如果失败则尝试绝对导入
                try:
                    m = importlib.import_module(import_name, package_name)
                except (ImportError, ValueError):
                    # 如果是在 IDE 或非标准结构运行，尝试直接导入
                    m = importlib.import_module(f"androidemu.java.classes.{mod_name}")

                # 检查模块中的类
                clsList = inspect.getmembers(m, inspect.isclass)
                for name, clz in clsList:
                    if isinstance(clz, JavaClassDef) and clz is not JavaClassDef:
                        if clz.__module__ == m.__name__:
                            if clz.jvm_name not in preload_classes:
                                preload_classes[clz.jvm_name] = clz
            except Exception as e:
                logger.warning(f"Failed to load class module {mod_name}: {e}")

        # 注册到 ClassLoader
        for clz in preload_classes.values():
            self.java_classloader.add_class(clz)

        # 注册 ClassLoader 自身
        self.java_classloader.add_class(JavaClassLoader)

    def __init__(
        self,
        vfs_root: str = None,
        config_path: str = None,
        vfp_inst_set: bool = True,
        arch: int = emu_const.ARCH_ARM32,
        muti_task: bool = False,
    ):
        if vfs_root is None:
            vfs_root = os.path.join(os.path.dirname(__file__), "data", "vfs")

        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(__file__), "data", "emu_cfg", "default.json"
            )

        self.config = config.Config(config_path)
        self.__arch = arch
        self.__support_muti_task = muti_task
        self.__pcb = pcb.Pcb()

        logger.info(
            f"Emulator Init: PID={self.__pcb.get_pid()}, Arch={'ARM64' if arch == emu_const.ARCH_ARM64 else 'ARM32'}"
        )

        sp_reg = 0
        if arch == emu_const.ARCH_ARM32:
            self.__ptr_sz = 4
            self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            if vfp_inst_set:
                self.__enable_vfp32()

            sp_reg = UC_ARM_REG_SP
            self.call_native = self.__call_native32
            self.call_native_return_2reg = self.__call_native_return_2reg32

        elif arch == emu_const.ARCH_ARM64:
            self.__ptr_sz = 8
            self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            if vfp_inst_set:
                self.__enable_vfp64()

            sp_reg = UC_ARM64_REG_SP
            self.call_native = self.__call_native64
            self.call_native_return_2reg = self.__call_native_return_2reg64
        else:
            raise RuntimeError(f"Unsupported architecture: {arch}")

        self.__vfs_root = vfs_root

        # 初始化 System Properties
        self._init_system_properties(arch)

        # 内存映射初始化
        self.memory = MemoryMap(
            self.mu,
            config.MAP_ALLOC_BASE,
            config.MAP_ALLOC_BASE + config.MAP_ALLOC_SIZE,
        )

        # 映射栈空间
        self.memory.map(
            config.STACK_ADDR, config.STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE
        )
        self.mu.reg_write(sp_reg, config.STACK_ADDR + config.STACK_SIZE)

        # 调度器
        self.__sch = Scheduler(self)

        # Syscall Handler
        # 修复：传递 arch 参数
        self.__syscall_handler = SyscallHandlers(self.mu, self.__sch, self.get_arch())

        # Hooker (Trampoline) 区域映射
        self.memory.map(
            config.BRIDGE_MEMORY_BASE,
            config.BRIDGE_MEMORY_SIZE,
            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
        )
        self.__hooker = Hooker(
            self, config.BRIDGE_MEMORY_BASE, config.BRIDGE_MEMORY_SIZE
        )

        # 初始化各个子系统
        self.__mem_handler = MemorySyscallHandler(
            self, self.memory, self.__syscall_handler
        )

        # 修复：SyscallHooks 初始化
        self.__syscall_hooks = SyscallHooks(self, self.config, self.__syscall_handler)

        self.__vfs = VirtualFileSystem(
            self, vfs_root, self.config, self.__syscall_handler, self.memory
        )

        self.java_classloader = JavaClassLoader()
        self.java_vm = JavaVM(self, self.java_classloader, self.__hooker)

        self.modules = Modules(self, self.__vfs_root)
        self.__sym_hooks = SymbolHooks(
            self, self.modules, self.__hooker, self.__vfs_root
        )

        # 加载 Java 类
        self.__add_classes()

        # Hack: JMethodID 内存区域
        self.memory.map(
            config.JMETHOD_ID_BASE,
            0x2000,
            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
        )

        # Signal Trampoline Mapping
        self.memory.map(
            config.SIGRETURN_TRAMPOLINE_ADDR,
            config.SIGRETURN_TRAMPOLINE_SIZE,
            UC_PROT_READ | UC_PROT_EXEC,
        )
        self._init_sighandler_trampoline()

        # 映射系统关键文件和内存页
        self._map_system_memory(arch)

    def _init_system_properties(self, arch):
        common_props = {
            "libc.debug.malloc.options": "",
            "ro.product.manufacturer": "samsung",
            "ro.debuggable": "0",
            "ro.product.model": "SM-G930F",
            "ro.hardware": "samsungexynos8890",
            "ro.product.board": "samsungexynos8890",
            "ro.product.device": "herolte",
            "ro.build.type": "user",
            "ro.secure": "1",
            "wifi.interface": "wlan0",
            "ro.product.brand": "Samsung",
            "ro.build.id": "MMB29K",
            "ro.build.display.id": "MMB29K",
            "ro.build.version.incremental": "user.20160101",
        }

        if arch == emu_const.ARCH_ARM32:
            self.system_properties = {
                **common_props,
                "ro.build.version.sdk": "19",
                "ro.build.version.release": "4.4.4",
                "persist.sys.dalvik.vm.lib": "libdvm.so",
                "ro.product.cpu.abi": "armeabi-v7a",
                "ro.product.cpu.abi2": "armeabi",
            }
        else:
            self.system_properties = {
                **common_props,
                "ro.build.version.sdk": "23",
                "ro.build.version.release": "6.0.1",
                "persist.sys.dalvik.vm.lib2": "libart.so",
                "ro.product.cpu.abi": "arm64-v8a",
            }

    def _map_system_memory(self, arch):
        """映射系统相关的特殊内存区域"""
        # 1. Vectors (ARM32 only)
        if arch == emu_const.ARCH_ARM32:
            path = os.path.join(self.__vfs_root, "system/lib/vectors")
            if os.path.exists(path):
                vf = VirtualFile(
                    "[vectors]", misc_utils.my_open(path, os.O_RDONLY), path
                )
                self.memory.map(0xFFFF0000, 0x1000, UC_PROT_EXEC | UC_PROT_READ, vf, 0)
            else:
                # 即使文件不存在，也要 map 一块空的，防止访问崩溃
                self.memory.map(0xFFFF0000, 0x1000, UC_PROT_EXEC | UC_PROT_READ)

        # 2. app_process (用于模拟进程特征)
        bin_path = (
            "system/bin/app_process32"
            if arch == emu_const.ARCH_ARM32
            else "system/bin/app_process64"
        )
        path = os.path.join(self.__vfs_root, bin_path)

        if os.path.exists(path):
            sz = os.path.getsize(path)
            vf = VirtualFile(
                f"/{bin_path}", misc_utils.my_open(path, os.O_RDONLY), path
            )
            # 对齐到页大小 (0x1000)
            map_sz = (sz + 0xFFF) & ~0xFFF
            self.memory.map(0xAB006000, map_sz, UC_PROT_EXEC | UC_PROT_READ, vf, 0)
        else:
            logger.warning(f"app_process binary not found at {path}, skipping map.")

    def get_vfs_root(self):
        return self.__vfs_root

    @property
    def syscall_hooks(self):
        return self.__syscall_hooks

    def _init_sighandler_trampoline(self):
        # Write sigreturn syscall wrapper
        # ARM32: sigreturn = 119 (0x77), rt_sigreturn=173 (0xAD)
        # Often use rt_sigreturn in modern linux
        # mov r7, #173; swi 0
        if self.__arch == emu_const.ARCH_ARM32:
            # mov r7, #173 (0xAD) -> E3 A0 70 AD
            # svc 0 -> EF 00 00 00
            code = b"\xad\x70\xa0\xe3\x00\x00\x00\xef"
            self.mu.mem_write(config.SIGRETURN_TRAMPOLINE_ADDR, code)

        # ARM64: rt_sigreturn = 139 (0x8B)
        # mov x8, #139; svc 0
        elif self.__arch == emu_const.ARCH_ARM64:
            # mov x8, #139 -> D2 81 16 08 (0x139=313? no 139=0x8B)
            # movz x8, 0x8b -> 68 11 80 D2
            # svc 0 -> 01 00 00 D4
            # 139 = 0x8B
            # mov x8, 139 => D2801168 (verify: 100 139 << 0 => 0x8B << 5 )
            # KS: mov x8, 139 => 68 11 80 D2
            # D4000001 (svc 0)
            code = b"\x68\x11\x80\xd2\x01\x00\x00\xd4"
            self.mu.mem_write(config.SIGRETURN_TRAMPOLINE_ADDR, code)

    def load_library(self, filename: str, do_init: bool = True):
        if not os.path.dirname(filename):
            if self.__arch == emu_const.ARCH_ARM32:
                libdir = "system/lib"
            else:
                libdir = "system/lib64"

            path = os.path.join(self.__vfs_root, libdir, filename)
            if os.path.exists(path):
                filename = path

        return self.modules.load_module(filename, do_init)

    def call_symbol(self, module, symbol_name: str, *argv):
        symbol_addr = module.find_symbol(symbol_name)
        if symbol_addr is None:
            logger.error(
                f"Symbol '{symbol_name}' not found in module '{module.filename}'"
            )
            return None
        return self.call_native(symbol_addr, *argv)

    def __call_native32(self, addr: int, *argv):
        if not addr:
            raise ValueError("Native call address cannot be None/0")

        # 使用重构后的 native_write_args (支持浮点)
        native_write_args(self, *argv)

        self.__sch.exec(addr)
        return self.mu.reg_read(UC_ARM_REG_R0)

    def __call_native64(self, addr, *argv):
        if not addr:
            raise ValueError("Native call address cannot be None/0")

        logger.debug(f"Calling Native64 at 0x{addr:X} with args: {argv}")
        native_write_args(self, *argv)

        self.__sch.exec(addr)
        return self.mu.reg_read(UC_ARM64_REG_X0)

    def __call_native_return_2reg32(self, addr, *argv):
        res = self.__call_native32(addr, *argv)
        res_high = self.mu.reg_read(UC_ARM_REG_R1)
        return (res_high << 32) | res

    def __call_native_return_2reg64(self, addr, *argv):
        res = self.__call_native64(addr, *argv)
        res_high = self.mu.reg_read(UC_ARM64_REG_X1)
        return (res_high << 64) | res

    # Getters
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
