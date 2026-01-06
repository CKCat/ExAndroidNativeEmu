from loguru import logger
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object


class DexFile(
    Object, metaclass=JavaClassDef, jvm_name="dalvik/system/DexFile", jvm_super=Object
):
    def __init__(self):
        Object.__init__(self)

    @java_method_def(
        name="<init>",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def ctor(self, emu, file_name):
        logger.debug(f"DexFile_ctor {file_name.get_py_string()}")
        # Stub

    @staticmethod
    @java_method_def(
        name="loadDex",
        args_list=["jstring", "jstring", "jint"],
        signature="(Ljava/lang/String;Ljava/lang/String;I)Ldalvik/system/DexFile;",
        native=False,
    )
    def loadDex(emu, sourcePathName, outputPathName, flags):
        logger.debug(
            f"DexFile.loadDex({sourcePathName.get_py_string()}, {outputPathName.get_py_string()}, {flags})"
        )
        return DexFile()

    @java_method_def(
        name="entries", signature="()Ljava/util/Enumeration;", native=False
    )
    def entries(self, emu):
        # Return empty enumeration
        return None
