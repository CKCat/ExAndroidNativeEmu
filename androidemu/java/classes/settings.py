from loguru import logger

from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .string import String


class Secure(
    metaclass=JavaClassDef, jvm_name="android/provider/Settings$Secure"
):
    def __init__(self):
        pass

    @staticmethod
    @java_method_def(
        name="getString",
        args_list=["jobject", "jstring"],
        signature="(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;",
        native=False,
    )
    def getString(emu, resolver, s1):
        logger.debug(f"call getString {resolver} {s1}")
        pys1 = s1.get_py_string()
        if pys1 == "android_id":
            android_id = emu.config.get("android_id")
            return String(android_id)

        raise NotImplementedError()
        return String("")


class Settings(metaclass=JavaClassDef, jvm_name="android/provider/Settings"):
    def __init__(self):
        pass
