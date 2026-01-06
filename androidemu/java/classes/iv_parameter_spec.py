from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .array import ByteArray


class IvParameterSpec(
    Object,
    metaclass=JavaClassDef,
    jvm_name="javax/crypto/spec/IvParameterSpec",
    jvm_super=Object,
):
    def __init__(self, iv):
        Object.__init__(self)
        self.__iv = iv  # bytes

    @java_method_def(name="<init>", args_list=["[B"], signature="([B)V", native=False)
    def ctor(self, emu, iv):
        self.__iv = iv.get_py_string()

    @java_method_def(name="getIV", signature="()[B", native=False)
    def getIV(self, emu):
        return ByteArray(self.__iv)
