from loguru import logger

from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC

from ..const import emu_const
from ..utils.misc_utils import page_end


class MemorySyscallHandler:
    """
    :type mu Uc
    :type syscall_handler SyscallHandlers
    """

    def __init__(self, emu, memory, syscall_handler):
        self.__emu = emu
        self.__pcb = emu.get_pcb()
        self._memory = memory
        self.__emu = emu
        self.__pcb = emu.get_pcb()
        self._memory = memory
        self._syscall_handler = syscall_handler
        # Initialize brk at a fixed address (e.g. 0x05000000)
        # In a real scenario, this should follow the BSS of the executable.
        self.__brk_base = 0x05000000
        self.__brk_address = self.__brk_base

        if self.__emu.get_arch() == emu_const.ARCH_ARM32:
            self._syscall_handler.set_handler(0x2D, "brk", 1, self._handle_brk)
            self._syscall_handler.set_handler(0x5B, "munmap", 2, self._handle_munmap)
            self._syscall_handler.set_handler(
                0x7D, "mprotect", 3, self._handle_mprotect
            )
            self._syscall_handler.set_handler(0xA3, "mremap", 5, self._handle_mremap)
            self._syscall_handler.set_handler(0xC0, "mmap2", 6, self._handle_mmap2)
            self._syscall_handler.set_handler(0xDC, "madvise", 3, self._handle_madvise)
        else:
            # arm64
            self._syscall_handler.set_handler(0xD6, "brk", 1, self._handle_brk)
            self._syscall_handler.set_handler(0xD7, "munmap", 2, self._handle_munmap)
            self._syscall_handler.set_handler(0xD8, "mremap", 5, self._handle_mremap)
            self._syscall_handler.set_handler(
                0xE2, "mprotect", 3, self._handle_mprotect
            )
            # arm64 只有mmap调用，没有mmap2
            self._syscall_handler.set_handler(0xDE, "mmap", 6, self._handle_mmap)
            self._syscall_handler.set_handler(0xE9, "madvise", 3, self._handle_madvise)

    def _handle_brk(self, uc, brk):
        logger.debug(
            f"brk(0x{brk:08X}) called. Current brk: 0x{self.__brk_address:08X}"
        )

        if brk == 0:
            return self.__brk_address

        # Check for invalid values (simple check)
        if brk < self.__brk_base:
            return self.__brk_address

        # Calculate difference
        old_page_end = page_end(self.__brk_address)
        new_page_end = page_end(brk)

        if new_page_end > old_page_end:
            # Allocate more memory
            size = new_page_end - old_page_end
            logger.debug(
                f"brk: increasing heap by 0x{size:X} (0x{old_page_end:X} -> 0x{new_page_end:X})"
            )
            try:
                self._memory.map(old_page_end, size, UC_PROT_READ | UC_PROT_WRITE)
            except Exception as e:
                logger.error(f"brk failed to map memory: {e}")
                return self.__brk_address  # Failed to expand

        elif new_page_end < old_page_end:
            # Shrink memory
            size = old_page_end - new_page_end
            logger.debug(
                f"brk: shrinking heap by 0x{size:X} (0x{new_page_end:X} <- 0x{old_page_end:X})"
            )
            try:
                self._memory.unmap(new_page_end, size)
            except Exception as e:
                logger.error(f"brk failed to unmap memory: {e}")
                return self.__brk_address  # Failed to shrink

        self.__brk_address = brk
        return self.__brk_address

    def _handle_munmap(self, uc, addr, len_in):
        try:
            self._memory.unmap(addr, len_in)
            return 0
        except Exception as e:
            logger.error(f"munmap failed: {e}")
            return -1

    def _mmap_common(self, addr, length, prot, flags, fd, offset):
        # define	PROT_READ	0x04	/* pages can be read */
        # define	PROT_WRITE	0x02	/* pages can be written */
        # define	PROT_EXEC	0x01	/* pages can be executed */
        MAP_SHARED = 0x01
        MAP_PRIVATE = 0x02
        MAP_FIXED = 0x10
        MAP_ANONYMOUS = 0x20
        # define MAP_UNINITIALIZED 0x0

        if (flags & MAP_SHARED) and (flags & MAP_PRIVATE):
            logger.error("mmap: MAP_SHARED and MAP_PRIVATE are mutually exclusive")
            return -1  # EINVAL

        if flags & MAP_SHARED:
            # We don't support real shared memory (write-back to file)
            # But we can proceed treating it as private (no write-back)
            # effectively just reading the file.
            pass

        res = None
        if flags & MAP_FIXED:
            # Unmap existing mapping if any
            # self._memory.unmap(addr, length) # We should protect this against error if not mapped?
            # For now, let Unicorn handle it or implementation detail in memory_map
            # But unicorn raise error if mapped. So we MUST unmap.
            try:
                self._memory.unmap(addr, length)
            except Exception:
                pass  # Ignore if not mapped

        if flags & MAP_ANONYMOUS:
            res = self._memory.map(addr, length, prot)
        elif fd != 0xFFFFFFFF:  # If valid fd
            if fd <= 2:
                raise NotImplementedError(
                    f"Unsupported read operation for file descriptor {fd}."
                )

            if not self.__pcb.has_fd(fd):
                logger.error(f"mmap: Invalid file descriptor {fd}")
                return -1  # EBADF

            vf = self.__pcb.get_fd_detail(fd)
            # offset must be in bytes here
            res = self._memory.map(addr, length, prot, vf, offset)
        else:
            res = self._memory.map(addr, length, prot)

        logger.debug(f"mmap return 0x{res:08X}")
        return res

    def _handle_mmap2(self, mu, addr, length, prot, flags, fd, pgoffset):
        """
        void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset);
        """
        offset = pgoffset * 4096
        return self._mmap_common(addr, length, prot, flags, fd, offset)

    def _handle_mmap(self, mu, addr, length, prot, flags, fd, offset):
        """
        void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
        """
        return self._mmap_common(addr, length, prot, flags, fd, offset)

    def _handle_madvise(self, mu, start, len_in, behavior):
        """
        int madvise(void *addr, size_t length, int advice);
        The kernel is free to ignore the advice.
        On success madvise() returns zero. On error, it returns -1 and errno is set appropriately.
        """
        # We don't need your advise.
        return 0

    def _handle_mprotect(self, mu, addr, len_in, prot):
        """
        int mprotect(void *addr, size_t len, int prot);

        mprotect() changes protection for the calling process's memory page(s) containing any part of the address
        range in the interval [addr, addr+len-1]. addr must be aligned to a page boundary.
        """
        return self._memory.protect(addr, len_in, prot)

    def _handle_mremap(self, mu, old_address, old_size, new_size, flags, new_address):
        # void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */);
        # Support only basic expansion/shrink or MREMAP_MAYMOVE
        MREMAP_MAYMOVE = 1
        MREMAP_FIXED = 2

        logger.debug(
            f"mremap(0x{old_address:08X}, 0x{old_size:X}, 0x{new_size:X}, {flags}) called"
        )

        if new_size <= old_size:
            # Shrinking is easy, just unmap the tail?
            # actually munmap(old_address + new_size, old_size - new_size)
            # But we can just leave it or explicit unmap.
            # Returning old address is valid.
            return old_address

        # Expansion
        # Simplified: allocate new, copy, unmap old.
        # This invalidates pointers if moved. MREMAP_MAYMOVE allows it.
        if flags & MREMAP_MAYMOVE:
            # 1. Map new size somewhere
            new_ptr = self._memory.map(
                0, new_size, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC
            )  # Prot?
            # 2. Copy data
            data = mu.mem_read(old_address, old_size)
            mu.mem_write(new_ptr, data)
            # 3. Unmap old
            self._memory.unmap(old_address, old_size)
            return new_ptr

        # If cannot move, try to map at end? Usually fails in simple logic.
        return -1  # ENOMEM
