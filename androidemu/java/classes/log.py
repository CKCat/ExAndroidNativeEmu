from loguru import logger
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object


class Log(
    Object, metaclass=JavaClassDef, jvm_name="android/util/Log", jvm_super=Object
):
    def __init__(self):
        Object.__init__(self)

    @staticmethod
    @java_method_def(
        name="d",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)I",
        native=False,
    )
    def d(emu, tag, msg):
        logger.debug(f"{tag}: {msg}")
        return 0

    @staticmethod
    @java_method_def(
        name="i",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)I",
        native=False,
    )
    def i(emu, tag, msg):
        logger.info(f"{tag}: {msg}")
        return 0

    @staticmethod
    @java_method_def(
        name="w",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)I",
        native=False,
    )
    def w(emu, tag, msg):
        logger.warning(f"{tag}: {msg}")
        return 0

    @staticmethod
    @java_method_def(
        name="e",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)I",
        native=False,
    )
    def e(emu, tag, msg):
        logger.error(f"{tag}: {msg}")
        return 0

    @staticmethod
    @java_method_def(
        name="v",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)I",
        native=False,
    )
    def v(emu, tag, msg):
        logger.debug(f"{tag}: {msg}")
        return 0
