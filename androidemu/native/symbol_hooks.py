import random

from loguru import logger
from unicorn import UC_PROT_READ, UC_PROT_WRITE

from ..const import emu_const, soinfo as soinfo_const
from ..java.helpers.native_method import native_method
from ..utils import memory_helpers
from .asset_mgr_hooks import AssetManagerHooks


class SymbolHooks:
    def __init__(self, emu, modules, hooker, vfs_root):
        self._emu = emu
        self._modules = modules
        self.__vfs_root = vfs_root
        self.__thread_id = 32145

        modules.add_symbol_hook(
            "__system_property_get",
            hooker.write_function(self.system_property_get),
        )
        modules.add_symbol_hook("dlopen", hooker.write_function(self.dlopen))
        modules.add_symbol_hook("dlclose", hooker.write_function(self.dlclose))
        modules.add_symbol_hook("dladdr", hooker.write_function(self.dladdr))
        modules.add_symbol_hook("dlsym", hooker.write_function(self.dlsym))
        modules.add_symbol_hook(
            "dl_unwind_find_exidx",
            hooker.write_function(self.dl_unwind_find_exidx),
        )
        if not emu.get_muti_task_support():
            modules.add_symbol_hook(
                "pthread_create", hooker.write_function(self.pthread_create)
            )
            modules.add_symbol_hook(
                "pthread_join", hooker.write_function(self.pthread_join)
            )
            modules.add_symbol_hook(
                "pthread_detach", hooker.write_function(self.pthread_detach)
            )

        modules.add_symbol_hook("rand", hooker.write_function(self.rand))
        modules.add_symbol_hook("newlocale", hooker.write_function(self.newlocale))

        modules.add_symbol_hook("abort", hooker.write_function(self.abort))
        modules.add_symbol_hook("dlerror", hooker.write_function(self.nop("dlerror")))

        asset_hooks = AssetManagerHooks(emu, modules, hooker, vfs_root)
        asset_hooks.register()

    @native_method
    def system_property_get(self, uc, name_ptr, buf_ptr):
        name = memory_helpers.read_utf8(uc, name_ptr)
        logger.debug(f"Called __system_property_get({name}, 0x{buf_ptr:x})")

        if name in self._emu.system_properties:
            p = self._emu.system_properties[name]
            nread = len(p)
            memory_helpers.write_utf8(uc, buf_ptr, p)
            return nread
        else:
            logger.warning(f"{name} was not found in system_properties dictionary.")

        return 0

    @native_method
    def dlopen(self, uc, path_str):
        path = memory_helpers.read_utf8(uc, path_str)
        logger.debug(f"Called dlopen({path})")

        r = 0
        if path.find("/") < 0:
            # 如果是libxxx.so这种字符串，则直接从modules中查找
            for mod in self._modules.modules:
                if mod.filename.find(path) > -1:
                    r = mod.soinfo_ptr
                    logger.debug(f"Called dlopen({path}) return 0x{r:08x}")
                    return r

        # redirect path on matter what path in vm runing
        fullpath = self._modules.find_so_on_disk(path)
        if fullpath is not None:
            mod = self._emu.load_library(fullpath)
            r = mod.soinfo_ptr
        else:
            logger.debug(f"dlopen {path} not found!!!")
            r = 0

        logger.debug(f"Called dlopen({path}) return 0x{r:08x}")
        return r

    @native_method
    def dlclose(self, uc, handle):
        """
        The function dlclose() decrements the reference count on the dynamic library handle handle.
        If the reference count drops to zero and no other loaded libraries use symbols in it, then the dynamic library is unloaded.
        """
        logger.debug(f"Called dlclose(0x{handle:x})")
        return 0

    @native_method
    def dladdr(self, uc, addr, info_ptr):
        logger.debug(f"Called dladdr(0x{addr:x}, 0x{info_ptr:x})")

        for mod in self._modules.modules:
            if mod.base <= addr < mod.base + mod.size:
                if not hasattr(mod, "filename_ptr"):
                    # 使用模拟器内存映射来存储文件名，避免内存泄漏 (cache on module)
                    mod.filename_ptr = self._emu.memory.map(
                        0, len(mod.filename) + 1, UC_PROT_READ | UC_PROT_WRITE
                    )
                    memory_helpers.write_utf8(uc, mod.filename_ptr, mod.filename)

                dli_fname = mod.filename_ptr
                memory_helpers.write_ptrs_sz(
                    uc,
                    info_ptr,
                    [dli_fname, mod.base, 0, 0],
                    self._emu.get_ptr_size(),
                )
                logger.debug(
                    f"Called dladdr ok return path={mod.filename} base=0x{mod.base:08x}"
                )
                return 1

        logger.debug(f"Called dladdr(0x{addr:x}) not found")
        return 0

    @native_method
    def dlsym(self, uc, handle, symbol):
        symbol_str = memory_helpers.read_utf8(uc, symbol)
        logger.debug(f"Called dlsym(0x{handle:x}, {symbol_str})")
        global_handle = 0xFFFFFFFF
        if self._emu.get_arch() == emu_const.ARCH_ARM64:
            global_handle = 0

        if handle == global_handle:
            sym = self._modules.find_symbol_str(symbol_str)
        else:
            soinfo = handle
            base = -1

            if self._emu.get_arch() == emu_const.ARCH_ARM64:
                base = memory_helpers.read_ptr_sz(
                    uc,
                    soinfo + soinfo_const.SOINFO_BASE_OFFSET_ARM64,
                    self._emu.get_ptr_size(),
                )
            else:
                base = memory_helpers.read_ptr_sz(
                    uc,
                    soinfo + soinfo_const.SOINFO_BASE_OFFSET_ARM32,
                    self._emu.get_ptr_size(),
                )

            module = self._modules.find_module(base)

            if module is None:
                raise Exception(f"Module not found for address 0x{symbol:x}")

            sym = module.find_symbol(symbol_str)

        r = 0
        if sym is not None:
            r = sym

        logger.debug(f"Called dlsym(0x{handle:x}, {symbol_str}) return 0x{r:08X}")
        return r

    @native_method
    def abort(self, uc):
        raise RuntimeError("abort called!!!")

    @native_method
    def dl_unwind_find_exidx(self, uc, pc, pcount_ptr):
        return 0

    @native_method
    def pthread_create(self, uc, pthread_t_ptr, attr, start_routine, arg):
        logger.warning(f"pthread_create called start_routine [0x{start_routine:08X}]")
        # pthread_t结构体实际上只是一个long
        uc.mem_write(
            pthread_t_ptr,
            int(self.__thread_id).to_bytes(
                self._emu.get_ptr_size(), byteorder="little"
            ),
        )
        self.__thread_id = self.__thread_id + 1
        return 0

    @native_method
    def pthread_join(self, uc, pthread_t, retval):
        return 0

    @native_method
    def pthread_detach(self, uc, pthread_t):
        return 0

    @native_method
    def rand(self, uc):
        # 这个函数实现同random，但4.4的libc没有这个符号
        logger.info("rand call")
        r = random.randint(0, 0xFFFFFFFF)
        return r

    @native_method
    def newlocale(self, uc):
        # 4.4的libc太旧没有这个函数，先这样绕过
        logger.info("newlocale call return 0 skip")
        return 0

    def nop(self, name):
        @native_method
        def nop_inside(emu):
            raise NotImplementedError(f"Symbol hook not implemented {name}")

        return nop_inside
