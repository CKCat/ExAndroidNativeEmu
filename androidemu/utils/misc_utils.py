import os
import os.path
import platform

from loguru import logger

IS_WINDOWS = platform.system() == "Windows"


def vfs_path_to_system_path(vfs_root: str, path: str) -> str:
    if os.name == "nt":
        path = path.replace(":", "_")

    # Ensure path doesn't start with / if we want to join it successfully with join
    # but vfs path usually starts with /.
    if path.startswith("/") or path.startswith("\\"):
        path = path[1:]

    fullpath = os.path.join(vfs_root, path)
    logger.debug(f"vfs_path_to_system_path: {fullpath}")
    return fullpath


def system_path_to_vfs_path(vfs_root: str, path: str) -> str:
    return "/" + os.path.relpath(path, vfs_root)


PF_X = 0x1  # Executable
PF_W = 0x2  # Writable
PF_R = 0x4  # Readable

PAGE_SIZE = 0x1000


def page_start(addr: int) -> int:
    return addr & (~(PAGE_SIZE - 1))


def page_end(addr: int) -> int:
    return page_start(addr + (PAGE_SIZE - 1))


def get_segment_protection(prot_in: int) -> int:
    prot = 0

    if prot_in & PF_R != 0:
        prot |= 1

    if prot_in & PF_W != 0:
        prot |= 2

    if prot_in & PF_X != 0:
        prot |= 4

    return prot


def my_open(path: str, flag: int) -> int:
    if IS_WINDOWS:
        flag = flag | os.O_BINARY
    return os.open(path, flag)
