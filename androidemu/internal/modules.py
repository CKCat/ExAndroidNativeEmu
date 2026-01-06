import os

from loguru import logger
from unicorn import UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE
from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0
from unicorn.arm_const import UC_ARM_REG_C13_C0_3

from .. import config
from ..const import android
from ..const import emu_const, linux
from ..utils import memory_helpers, misc_utils
from ..utils.misc_utils import get_segment_protection, page_end, page_start
from ..utils.stack_helpers import StackHelper
from ..vfs.virtual_file import VirtualFile
from ..const import elf_const
from . import elf_reader
from .module import Module


class Modules:
    def __tls_init(self):
        sp_helpers = StackHelper(self.emu)

        pthread_internal_nptr = 0x400
        # 为pthread_internal预留空间，由于这个结构体跟libc的版本相关，暂时什么都不写
        thread_internal_ptr = sp_helpers.reserve(pthread_internal_nptr)

        stack_guard_ptr = sp_helpers.write_val(0x1000)

        # argv的实际字符串，目前只写一个
        argvs = android.DEFAULT_ARGV
        argvs_ptrs = []
        for argv in argvs:
            argv_str_ptr = sp_helpers.write_utf8(argv)
            argvs_ptrs.append(argv_str_ptr)
        #

        # Environment variables.
        env = android.DEFAULT_ENV
        env_ptrs = []
        for k in env:
            env_str = "%s=%s" % (k, env[k])
            env_ptr = sp_helpers.write_utf8(env_str)
            env_ptrs.append(env_ptr)

        sp_helpers.commit()
        ptr_sz = self.emu.get_ptr_size()

        # auxv
        auxvs = {
            linux.AT_RANDOM: stack_guard_ptr,
            # Other aux vectors can be added here if needed
        }
        auxv_base = sp_helpers.reserve(0x100)
        auxv_offset = auxv_base
        for auxv_key in auxvs:
            # 填充auvx数组
            auxv_val = auxvs[auxv_key]
            memory_helpers.write_ptrs_sz(self.emu.mu, auxv_offset, auxv_key, ptr_sz)
            memory_helpers.write_ptrs_sz(
                self.emu.mu, auxv_offset + ptr_sz, auxv_val, ptr_sz
            )
            auxv_offset += 2 * ptr_sz

        # auvx数组0结尾
        memory_helpers.write_ptrs_sz(self.emu.mu, auxv_offset, 0, 2 * ptr_sz)

        env_base = sp_helpers.reserve(len(env_ptrs) + 1)
        env_offset = env_base
        # envp
        for env_ptr in env_ptrs:
            memory_helpers.write_ptrs_sz(self.emu.mu, env_offset, env_ptr, ptr_sz)
            env_offset += ptr_sz

        # 0结尾
        memory_helpers.write_ptrs_sz(self.emu.mu, env_offset, 0, ptr_sz)

        nargc = len(argvs)
        argv_base = sp_helpers.reserve(nargc + 1)
        argv_offset = argv_base
        # argv
        for argv_ptr in argvs_ptrs:
            memory_helpers.write_ptrs_sz(self.emu.mu, argv_offset, argv_ptr, ptr_sz)
            argv_offset += ptr_sz

        # 0结尾
        memory_helpers.write_ptrs_sz(self.emu.mu, argv_offset, 0, ptr_sz)

        # KernelArgumentBlock
        # int argc;
        # char** argv;
        # char** envp;
        # Elf32_auxv_t* auxv;
        # abort_msg_t** abort_message_ptr;
        kernel_args_base = sp_helpers.reserve(5)
        memory_helpers.write_ptrs_sz(self.emu.mu, kernel_args_base, nargc, ptr_sz)
        memory_helpers.write_ptrs_sz(
            self.emu.mu, kernel_args_base + ptr_sz, argv_base, ptr_sz
        )
        memory_helpers.write_ptrs_sz(
            self.emu.mu, kernel_args_base + 2 * ptr_sz, env_base, ptr_sz
        )
        memory_helpers.write_ptrs_sz(
            self.emu.mu, kernel_args_base + 3 * ptr_sz, auxv_base, ptr_sz
        )
        memory_helpers.write_ptrs_sz(
            self.emu.mu, kernel_args_base + 4 * ptr_sz, 0, ptr_sz
        )

        # tls单独一个区域，不放在stack中
        self.emu.mu.mem_map(
            config.TLS_BASE, config.TLS_SIZE, UC_PROT_WRITE | UC_PROT_READ
        )
        tls_ptr = config.TLS_BASE
        mu = self.emu.mu
        # TLS_SLOT_SELF
        memory_helpers.write_ptrs_sz(mu, tls_ptr, tls_ptr, ptr_sz)
        # TLS_SLOT_THREAD_ID
        memory_helpers.write_ptrs_sz(mu, tls_ptr + ptr_sz, thread_internal_ptr, ptr_sz)
        # TLS_SLOT_ERRNO
        self.__errno_ptr = tls_ptr + 2 * ptr_sz
        # TLS_SLOT_BIONIC_PREINIT
        memory_helpers.write_ptrs_sz(mu, tls_ptr + 3 * ptr_sz, kernel_args_base, ptr_sz)
        arch = self.emu.get_arch()

        if arch == emu_const.ARCH_ARM32:
            mu.reg_write(UC_ARM_REG_C13_C0_3, tls_ptr)
        else:
            mu.reg_write(UC_ARM64_REG_TPIDR_EL0, tls_ptr)

        sp_helpers.commit()

    """
    :type emu androidemu.emulator.Emulator
    :type modules list[Module]
    """

    def __init__(self, emu, vfs_root: VirtualFile):
        self.emu = emu
        self.modules = list()
        self.symbol_hooks = dict()
        self.counter_memory = config.BASE_ADDR
        self.__vfs_root = vfs_root
        soinfo_area_sz = 0x40000
        self.__soinfo_area_base = emu.memory.map(
            0, soinfo_area_sz, UC_PROT_WRITE | UC_PROT_READ
        )
        self.__errno_ptr = 0
        self.filename = ""
        self.__tls_init()

    def __get_ld_library_path(self):
        if self.emu.get_arch() == emu_const.ARCH_ARM32:
            return ["/system/lib/"]
        else:
            return ["/system/lib64/"]

    def find_so_on_disk(self, so_path: str):
        if os.path.isabs(so_path):
            path = misc_utils.vfs_path_to_system_path(self.__vfs_root, so_path)
            return path
        else:
            ld_library_path = self.__get_ld_library_path()
            so_name = so_path
            for lib_path in ld_library_path:
                lib_full_path = f"{lib_path}{so_name}"
                vfs_lib_path = misc_utils.vfs_path_to_system_path(
                    self.__vfs_root, lib_full_path
                )
                if os.path.exists(vfs_lib_path):
                    return vfs_lib_path
        return None

    def add_symbol_hook(self, symbol_name, addr):
        self.symbol_hooks[symbol_name] = addr

    def find_symbol(self, addr):
        for module in self.modules:
            if addr in module.symbol_lookup:
                return module.symbol_lookup[addr]
        return None, None

    def find_symbol_str(self, symbol_str):
        for module in self.modules:
            sym = module.find_symbol(symbol_str)
            if sym is not None:
                return sym
        return None

    def find_module(self, addr):
        for module in self.modules:
            if module.base == addr:
                return module
        return None

    def find_module_by_name(self, filename):
        absp1 = os.path.abspath(filename)
        for m in self.modules:
            absm = os.path.abspath(m.filename)
            if absp1 == absm:
                return m

    def mem_reserve(self, start, end):
        size_aligned = page_end(end) - page_start(start)
        ret = self.counter_memory
        self.counter_memory += size_aligned
        return ret

    def _calculate_bounds(self, load_segments):
        """Calculate the memory bounds for load segments."""
        bound_low = 0xFFFFFFFFFFFFFFFF
        bound_high = 0
        for segment in load_segments:
            p_memsz = segment["p_memsz"]
            if p_memsz == 0:
                continue
            p_vaddr = segment["p_vaddr"]
            if bound_low > p_vaddr:
                bound_low = p_vaddr
            high = p_vaddr + p_memsz

            if bound_high < high:
                bound_high = high
        return bound_low, bound_high

    def _map_segment(self, segment, load_bias, vf):
        """Map a single ELF segment into memory."""
        p_flags = segment["p_flags"]
        prot = get_segment_protection(p_flags)
        prot = prot if prot != 0 else UC_PROT_ALL

        p_vaddr = segment["p_vaddr"]
        seg_start = load_bias + p_vaddr
        seg_page_start = page_start(seg_start)
        p_offset = segment["p_offset"]
        file_start = p_offset
        p_filesz = segment["p_filesz"]
        file_end = file_start + p_filesz
        file_page_start = page_start(file_start)
        file_length = file_end - file_page_start

        if file_length > 0:
            self.emu.memory.map(seg_page_start, file_length, prot, vf, file_page_start)

        p_memsz = segment["p_memsz"]
        seg_end = seg_start + p_memsz
        seg_page_end = page_end(seg_end)
        seg_file_end = page_end(seg_start + p_filesz)

        if seg_page_end > seg_file_end:
            self.emu.memory.map(seg_file_end, seg_page_end - seg_file_end, prot)

    def _load_dependencies(self, reader, filename):
        so_needed = reader.get_so_need()
        for so_name in so_needed:
            path = self.find_so_on_disk(so_name)
            if path is None:
                logger.warning(
                    f"{so_name} needed by {filename} do not exist in {self.__vfs_root}"
                )
                continue
            self.load_module(path)

    def _process_relocation(self, load_bias, symbols, symbols_resolved, rels, reader):
        for rel_name in rels:
            rel_tbl = rels[rel_name]
            for rel in rel_tbl:
                r_info_sym = rel["r_info_sym"]
                sym_value = symbols[r_info_sym]["st_value"]
                rel_addr = load_bias + rel["r_offset"]
                rel_info_type = rel["r_info_type"]
                sym_name = reader.get_dyn_string_by_rel_sym(r_info_sym)

                if rel_info_type == elf_const.R_ARM_ABS32:
                    if sym_name in symbols_resolved:
                        sym_addr = symbols_resolved[sym_name]
                        value_orig = int.from_bytes(
                            self.emu.mu.mem_read(rel_addr, 4), "little"
                        )
                        self.emu.mu.mem_write(
                            rel_addr, (sym_addr + value_orig).to_bytes(4, "little")
                        )

                elif rel_info_type in (
                    elf_const.R_AARCH64_ABS64,
                    elf_const.R_AARCH64_ABS32,
                ):
                    if sym_name in symbols_resolved:
                        sym_addr = symbols_resolved[sym_name]
                        value_orig = int.from_bytes(
                            self.emu.mu.mem_read(rel_addr, 8), "little"
                        )
                        addend = rel["r_addend"]
                        self.emu.mu.mem_write(
                            rel_addr,
                            (sym_addr + value_orig + addend).to_bytes(8, "little"),
                        )

                elif rel_info_type in (
                    elf_const.R_ARM_GLOB_DAT,
                    elf_const.R_ARM_JUMP_SLOT,
                ):
                    if sym_name in symbols_resolved:
                        val = symbols_resolved[sym_name]
                        self.emu.mu.mem_write(rel_addr, val.to_bytes(4, "little"))

                elif rel_info_type in (
                    elf_const.R_AARCH64_GLOB_DAT,
                    elf_const.R_AARCH64_JUMP_SLOT,
                ):
                    if sym_name in symbols_resolved:
                        val = symbols_resolved[sym_name]
                        addend = rel["r_addend"]
                        self.emu.mu.mem_write(
                            rel_addr, (val + addend).to_bytes(8, "little")
                        )

                elif rel_info_type == elf_const.R_ARM_RELATIVE:
                    if sym_value == 0:
                        value_orig = int.from_bytes(
                            self.emu.mu.mem_read(rel_addr, 4), "little"
                        )
                        self.emu.mu.mem_write(
                            rel_addr, (load_bias + value_orig).to_bytes(4, "little")
                        )
                    else:
                        raise NotImplementedError("R_ARM_RELATIVE with sym_value != 0")

                elif rel_info_type == elf_const.R_AARCH64_RELATIVE:
                    if sym_value == 0:
                        addend = rel["r_addend"]
                        self.emu.mu.mem_write(
                            rel_addr, (load_bias + addend).to_bytes(8, "little")
                        )
                    else:
                        raise NotImplementedError(
                            "R_AARCH64_RELATIVE with sym_value != 0"
                        )
                else:
                    # Some relocations (like R_ARM_NONE) can be ignored or warned about
                    pass

    def load_module(self, filename, do_init=True):
        self.filename = filename
        m = self.find_module_by_name(filename)
        if m is not None:
            return m

        logger.debug(f"Loading module '{filename}'.")
        reader = elf_reader.ELFReader(filename)

        is_arm32 = self.emu.get_arch() == emu_const.ARCH_ARM32
        if is_arm32 and not reader.is_elf32():
            raise RuntimeError(f"arch is ARCH_ARM32 but so {filename} is not elf32!!!")
        elif not is_arm32 and reader.is_elf32():
            raise RuntimeError(f"arch is ARCH_ARM64 but so {filename} is elf32!!!")

        load_segments = reader.get_load()
        bound_low, bound_high = self._calculate_bounds(load_segments)

        load_base = self.mem_reserve(bound_low, bound_high)
        load_bias = load_base - bound_low

        vf = VirtualFile(
            misc_utils.system_path_to_vfs_path(self.__vfs_root, filename),
            misc_utils.my_open(filename, os.O_RDONLY),
            filename,
        )

        for segment in load_segments:
            self._map_segment(segment, load_bias, vf)

        self._load_dependencies(reader, filename)

        symbols = reader.get_symbols()
        symbols_resolved = dict()

        for symbol in symbols:
            symbol_address = self._elf_get_symval(load_bias, symbol)
            if symbol_address is not None:
                symbols_resolved[symbol["name"]] = symbol_address

        self._process_relocation(
            load_bias, symbols, symbols_resolved, reader.get_rels(), reader
        )

        init_array_addr, init_array_size = reader.get_init_array()
        init_array = []
        init_addr = reader.get_init()

        if init_addr != 0:
            init_array.append(load_bias + init_addr)

        init_item_sz = 4 if is_arm32 else 8

        for _ in range(int(init_array_size / init_item_sz)):
            b = self.emu.mu.mem_read(load_bias + init_array_addr, init_item_sz)
            fun_ptr = int.from_bytes(b, byteorder="little", signed=False)
            if fun_ptr != 0:
                init_array.append(fun_ptr)
            init_array_addr += init_item_sz

        write_sz = reader.write_soinfo(
            self.emu.mu, load_base, load_bias, self.__soinfo_area_base
        )

        module = Module(
            filename,
            load_base,
            bound_high - bound_low,
            symbols_resolved,
            init_array,
            self.__soinfo_area_base,
        )
        self.modules.append(module)
        self.__soinfo_area_base += write_sz

        if do_init:
            module.call_init(self.emu)

        logger.info(f"finish load lib {filename} base 0x{load_base:08X}.")
        return module

    def _elf_get_symval(self, load_bias, symbol):
        name = symbol["name"]
        if name in self.symbol_hooks:
            return self.symbol_hooks[name]

        if symbol["st_shndx"] == elf_reader.SHN_UNDEF:
            # External symbol, lookup value.
            target = self._elf_lookup_symbol(name)
            if target is None:
                # Extern symbol not found
                if symbol["st_info_bind"] == elf_reader.STB_WEAK:
                    # Weak symbol initialized as 0
                    return 0
                else:
                    if not name:
                        # Empty symbol name (often STT_SECTION), ignore or debug log
                        # logger.debug(f"=> Undefined external symbol with empty name at 0x{symbol['st_value']:x}")
                        pass
                    else:
                        logger.error(f"=> Undefined external symbol: {name}")
                    return None
            else:
                return target
        elif symbol["st_shndx"] == elf_reader.SHN_ABS:
            # Absolute symbol.
            return load_bias + symbol["st_value"]
        else:
            # Internally defined symbol.
            return load_bias + symbol["st_value"]

    def _elf_lookup_symbol(self, name):
        for module in self.modules:
            if name in module.symbols:
                addr = module.symbols[name]
                if addr != 0:
                    return addr

        return None

    def __iter__(self):
        for x in self.modules:
            yield x
