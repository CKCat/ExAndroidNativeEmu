import os

from loguru import logger
from unicorn import UC_ERR_MAP, UC_PROT_READ, UC_PROT_WRITE, UcError

from ..utils.misc_utils import page_end

# android中，不论64还是32，PAGE_SIZE都是4096，android 15 开始支持 16k 的页
PAGE_SIZE = 0x1000


class MemoryMap:
    def check_addr(self, addr, prot):
        for r in self.__mu.mem_regions():
            if addr >= r[0] and addr < r[1] and prot & r[2]:
                return True

        return False

    @staticmethod
    def __is_page_align(addr):
        return addr % PAGE_SIZE == 0

    @staticmethod
    def __is_overlap(addr1, end1, addr2, end2):
        r = (
            (addr1 <= addr2 and end1 >= end2)
            or (addr2 <= addr1 and end2 >= end1)
            or (end1 > addr2 and addr1 < end2)
            or (end2 > addr1 and addr2 < end1)
        )
        return r

    def __init__(self, mu, alloc_min_addr, alloc_max_addr):
        self.__mu = mu
        self._alloc_min_addr = alloc_min_addr
        self._alloc_max_addr = alloc_max_addr
        self.__file_map_addr = {}

    def __map(self, address, size, prot=UC_PROT_READ | UC_PROT_WRITE):
        if size <= 0:
            raise Exception("Heap map size was <= 0.")
        try:
            if address == 0:
                regions = []
                for r in self.__mu.mem_regions():
                    regions.append(r)

                regions.sort()
                map_base = -1
                l_regions = len(regions)
                if l_regions < 1:
                    map_base = self._alloc_min_addr
                else:
                    prefer_start = self._alloc_min_addr
                    next_loop = True
                    while next_loop:
                        next_loop = False
                        for r in regions:
                            if self.__is_overlap(
                                prefer_start,
                                prefer_start + size,
                                r[0],
                                r[1] + 1,
                            ):
                                prefer_start = r[1] + 1
                                next_loop = True
                                break

                    map_base = prefer_start

                if (
                    map_base > self._alloc_max_addr
                    or map_base < self._alloc_min_addr
                ):
                    raise RuntimeError(
                        "mmap error map_base 0x%08X out of range (0x%08X-0x%08X)!!!"
                        % (map_base, self._alloc_min_addr, self._alloc_max_addr)
                    )

                logger.debug(
                    "before mem_map addr:0x%08X, sz:0x%08X" % (map_base, size)
                )

                self.__mu.mem_map(map_base, size, perms=prot)
                return map_base

            else:
                # MAP_FIXED
                try:
                    self.__mu.mem_map(address, size, perms=prot)
                except UcError as e:
                    if e.errno == UC_ERR_MAP:
                        blocks = set()
                        extra_protect = set()
                        for b in range(address, address + size, 0x1000):
                            blocks.add(b)

                        for r in self.__mu.mem_regions():
                            # 修改属性
                            raddr = r[0]
                            rend = r[1] + 1
                            for b in range(raddr, rend, 0x1000):
                                if b in blocks:
                                    blocks.remove(b)
                                    extra_protect.add(b)

                        for b_map in blocks:
                            self.__mu.mem_map(b_map, 0x1000, prot)

                        for b_protect in extra_protect:
                            self.__mu.mem_protect(b_protect, 0x1000, prot)

                return address

        except UcError:
            # impossible
            for r in self.__mu.mem_regions():
                logger.debug(
                    f"region begin :0x{r[0]:08X} end:0x{r[1]:08X}, prot:{r[2]}"
                )

            raise

    def __read_fully(self, fd, size):
        b_read = os.read(fd, size)
        # print (b_read)
        sz_read = len(b_read)
        if sz_read <= 0:
            return b_read

        sz_left = size - sz_read
        while sz_left > 0:
            this_read = os.read(fd, sz_left)
            len_this_read = len(this_read)
            # print (len_this_read)
            if len_this_read <= 0:
                break
            b_read = b_read + this_read
            sz_left = sz_left - len_this_read

        return b_read

    def map(
        self,
        address,
        size,
        prot=UC_PROT_READ | UC_PROT_WRITE,
        vf=None,
        offset=0,
    ):
        if not self.__is_page_align(address):
            raise RuntimeError(
                "map addr was not multiple of page size (%d, %d)."
                % (address, PAGE_SIZE)
            )

        logger.debug(
            f"map addr:0x{address:08X}, end:0x{address + size:08X}, sz:0x{size:08X} off=0x{offset:08X}"
        )
        # traceback.print_stack()
        al_address = address
        al_size = page_end(al_address + size) - al_address
        res_addr = self.__map(al_address, al_size, prot)
        if res_addr != -1 and vf is not None:
            # 需要mmap映射文件的时候,开辟一块内存,并将文件内容复制过去模拟
            if not self.__is_page_align(offset):
                raise RuntimeError(
                    "map offset was not multiple of page size (%d, %d)."
                    % (offset, PAGE_SIZE)
                )

            if offset > 0xFFFFFFFF:
                raise NotImplementedError(
                    "map offset %d > 4G not support now" % offset
                )

            ori_off = os.lseek(vf.descriptor, 0, os.SEEK_CUR)

            # logging.debug("mmap file ori_off %d"%(ori_off,))
            os.lseek(vf.descriptor, offset, os.SEEK_SET)
            data = self.__read_fully(vf.descriptor, size)
            logger.debug(
                f"read for offset {offset} sz {size} data sz:{len(data)}"
            )
            self.__mu.mem_write(res_addr, data)
            self.__file_map_addr[res_addr] = (res_addr + al_size, offset, vf)
            os.lseek(vf.descriptor, ori_off, os.SEEK_SET)

        return res_addr

    def protect(self, addr, len, prot):
        if not self.__is_page_align(addr):
            raise Exception(
                "addr was not multiple of page size (%d, %d)."
                % (addr, PAGE_SIZE)
            )

        len_in = page_end(addr + len) - addr
        try:
            self.__mu.mem_protect(addr, len_in, prot)
        except UcError:
            # TODO:just for debug
            logger.warning(
                f"Warning mprotect with addr: 0x{addr:08X} len: 0x{len:08X} prot:0x{prot:08X} failed!!!"
            )
            # self.dump_maps(sys.stdout)
            # raise
            return -1

        return 0

    def unmap(self, addr, size):
        if not self.__is_page_align(addr):
            raise RuntimeError(
                "addr was not multiple of page size (%d, %d)."
                % (addr, PAGE_SIZE)
            )

        size = page_end(addr + size) - addr
        try:
            logger.debug(
                f"unmap 0x{addr:08X} sz=0x{size:08X} end=0x{addr + size:08X}"
            )
            if addr in self.__file_map_addr:
                file_map_attr = self.__file_map_addr[addr]
                if addr + size != file_map_attr[0]:
                    raise RuntimeError(
                        f"unmap error, range 0x{addr:08X}-0x{addr + size:08X} does not match file map range 0x{addr:08X}-0x{file_map_attr[0]:08X} from file {file_map_attr[2].name}"
                    )

                self.__file_map_addr.pop(addr)

            self.__mu.mem_unmap(addr, size)

        except UcError:
            # TODO:just for debug

            for r in self.__mu.mem_regions():
                logger.exception(
                    f"region begin :0x{r[0]:08X} end:0x{r[1]:08X}, prot:{r[2]}"
                )

            raise

        return 0

    def __get_map_attr(self, start, end):
        for addr in self.__file_map_addr:
            v = self.__file_map_addr[addr]
            mstart = addr
            mend = v[0]
            if start >= mstart and end <= mend:
                vf = v[2]
                return v[1], vf.name

        return 0, ""

    def __get_attrs(self, region):
        r = "r" if region[2] & 0x1 else "-"
        w = "w" if region[2] & 0x2 else "-"
        x = "x" if region[2] & 0x4 else "-"
        prot = f"{r}{w}{x}"
        off, name = self.__get_map_attr(region[0], region[1] + 1)
        return (region[0], region[1] + 1, prot, off, name)

    # dump maps like /proc/self/maps
    def dump_maps(self, stream):
        regions = []
        for region in self.__mu.mem_regions():
            regions.append(region)

        regions.sort()

        """
        for region in regions:
            logger.debug(f"region begin :0x{region[0]:08X} end:0x{region[1]:08X}, prot:{region[2]}")
        """

        n = len(regions)
        if n < 1:
            return
        output = []
        last_attr = self.__get_attrs(regions[0])
        start = last_attr[0]
        for i in range(1, n):
            region = regions[i]
            attr = self.__get_attrs(region)
            if last_attr[1] == attr[0] and last_attr[2:] == attr[2:]:
                pass
            else:
                output.append((start,) + last_attr[1:])
                start = attr[0]

            last_attr = attr

        output.append((start,) + last_attr[1:])

        for item in output:
            line = "%08x-%08x %s %08x 00:00 0 \t\t %s\n" % (
                item[0],
                item[1],
                item[2],
                item[3],
                item[4],
            )
            stream.write(line)
