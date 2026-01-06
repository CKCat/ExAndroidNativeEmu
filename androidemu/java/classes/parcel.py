from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from loguru import logger


class Parcel(
    Object, metaclass=JavaClassDef, jvm_name="android/os/Parcel", jvm_super=Object
):
    def __init__(self):
        Object.__init__(self)
        self.__data = []
        self.__pos = 0

    @staticmethod
    @java_method_def(name="obtain", signature="()Landroid/os/Parcel;", native=False)
    def obtain(emu):
        return Parcel()

    @java_method_def(name="recycle", signature="()V", native=False)
    def recycle(self, emu):
        self.__data = []
        self.__pos = 0

    @java_method_def(
        name="writeInt", args_list=["jint"], signature="(I)V", native=False
    )
    def writeInt(self, emu, val):
        self.__data.append(val)

    @java_method_def(name="readInt", signature="()I", native=False)
    def readInt(self, emu):
        if self.__pos < len(self.__data):
            val = self.__data[self.__pos]
            self.__pos += 1
            return val
        return 0
