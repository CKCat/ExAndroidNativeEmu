from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .stream import OutputStream
from loguru import logger
import os


class FileOutputStream(
    OutputStream,
    metaclass=JavaClassDef,
    jvm_name="java/io/FileOutputStream",
    jvm_super=OutputStream,
):
    def __init__(self):
        OutputStream.__init__(self)
        self.__py_file = None

    @java_method_def(
        name="<init>",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def ctor_string(self, emu, path_str):
        path = path_str.get_py_string()
        logger.debug(f"FileOutputStream <init> {path}")
        try:
            self.__py_file = open(path, "wb")
            OutputStream.__init__(self, py_file_obj=self.__py_file)
        except Exception as e:
            logger.error(f"Failed to open output file {path}: {e}")
            pass

    @java_method_def(
        name="<init>",
        args_list=["Ljava/io/File;"],
        signature="(Ljava/io/File;)V",
        native=False,
    )
    def ctor_file(self, emu, file_obj):
        # Stub for File object access
        # path = file_obj.getPath()
        pass
