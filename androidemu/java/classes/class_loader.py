from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String


class BaseClassLoader(
    Object,
    metaclass=JavaClassDef,
    jvm_name="dalvik/system/BaseDexClassLoader",
    jvm_super=Object,
):
    def __init__(self):
        Object.__init__(self)

    @java_method_def(
        name="loadClass",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/Class;",
        native=False,
    )
    def loadClass(self, emu, name):
        # Stub: Just return None or verify if we can return a Class object
        # Returning Class object here is tricky because we need java.lang.Class wrapper
        # For now, return None or throw
        raise NotImplementedError()
