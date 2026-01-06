from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def


class ArrayMap(metaclass=JavaClassDef, jvm_name="android/util/ArrayMap"):
    def __init__(self, arr):
        self.__array = arr

    @java_method_def(name="size", signature="()I", native=False)
    def size(self, emu):
        return len(self.__array)

    @java_method_def(
        name="valueAt",
        args_list=["jint"],
        signature="(I)Ljava/lang/Object;",
        native=False,
    )
    def valueAt(self, emu, id):
        return self.__array[id]
