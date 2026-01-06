from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .stream import InputStream
from loguru import logger
import os


class FileInputStream(
    InputStream,
    metaclass=JavaClassDef,
    jvm_name="java/io/FileInputStream",
    jvm_super=InputStream,
):
    def __init__(self, emu, file_path):
        # file_path might be absolute or relative to vfs_root defined in emulator?
        # Emulator has vfs_root.
        # But here we are passed 'emu' in ctor? Or we resolve path before.
        # The Java ctor takes String.
        InputStream.__init__(self)
        self.__path = file_path
        self.__py_file = None

    @java_method_def(
        name="<init>",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def ctor_string(self, emu, path_str):
        path = path_str.get_py_string()
        logger.debug(f"FileInputStream <init> {path}")
        # Resolve path via emulator VFS logic
        # For now, we assume simple path mapping or absolute path on host if allowed,
        # but robust emu should map.
        # Let's try to find it in VFS directly if possible or relative to current dir.

        # We need access to VFS or assume simple open.
        # Since we don't have direct VFS reference easily here without emu instance in __init__,
        # we do it in ctor method which has emu.

        # Simple hack: try open relative to root or absolute
        try:
            # Check proper vfs access later.
            self.__py_file = open(path, "rb")
            InputStream.__init__(self, py_file_obj=self.__py_file)
        except Exception as e:
            logger.error(f"Failed to open input file {path}: {e}")
            # Should throw FileNotFoundException
            pass

    @java_method_def(
        name="<init>",
        args_list=["Ljava/io/File;"],
        signature="(Ljava/io/File;)V",
        native=False,
    )
    def ctor_file(self, emu, file_obj):
        # Invoke string ctor logic
        path = file_obj.get_path(emu)  # Assuming File has get_path
        self.ctor_string(emu, path)
