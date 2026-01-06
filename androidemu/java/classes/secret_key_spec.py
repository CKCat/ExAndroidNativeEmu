from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String
from .array import ByteArray


class SecretKeySpec(
    Object,
    metaclass=JavaClassDef,
    jvm_name="javax/crypto/spec/SecretKeySpec",
    jvm_super=Object,
):
    def __init__(self, key, algorithm):
        Object.__init__(self)
        self.__key = key  # bytes
        self.__algorithm = algorithm  # string

    @java_method_def(
        name="<init>",
        args_list=["[B", "jstring"],
        signature="([BLjava/lang/String;)V",
        native=False,
    )
    def ctor(self, emu, key, algorithm):
        self.__key = key.get_py_string()
        self.__algorithm = algorithm.get_py_string()

    @java_method_def(
        name="getAlgorithm", signature="()Ljava/lang/String;", native=False
    )
    def getAlgorithm(self, emu):
        return String(self.__algorithm)

    @java_method_def(name="getEncoded", signature="()[B", native=False)
    def getEncoded(self, emu):
        return ByteArray(self.__key)
