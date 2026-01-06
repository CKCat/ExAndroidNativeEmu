from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def


from .object import Object


class Set(Object, metaclass=JavaClassDef, jvm_name="java/util/Set", jvm_super=Object):
    def __init__(self, pyset):
        Object.__init__(self)
        self.__pyset = pyset

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        self.__pyset = set()

    def __len__(self):
        return len(self.__pyset)

    def __getitem__(self, key):
        return self.__pyset[key]

    @java_method_def(
        name="add",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)Z",
        native=False,
    )
    def add(self, emu, obj):
        if obj in self.__pyset:
            return False
        self.__pyset.add(obj)
        return True

    @java_method_def(
        name="remove",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)Z",
        native=False,
    )
    def remove(self, emu, obj):
        if obj in self.__pyset:
            self.__pyset.remove(obj)
            return True
        return False

    @java_method_def(
        name="contains",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)Z",
        native=False,
    )
    def contains(self, emu, obj):
        return obj in self.__pyset

    @java_method_def(name="iterator", signature="()Ljava/util/Iterator;", native=False)
    def iterator(self, emu):
        from .iterator import Iterator

        return Iterator(list(self.__pyset))

    @java_method_def(name="clear", signature="()V", native=False)
    def clear(self, emu):
        self.__pyset.clear()

    @java_method_def(name="isEmpty", signature="()Z", native=False)
    def isEmpty(self, emu):
        return len(self.__pyset) == 0

    @java_method_def(name="toArray", signature="()[Ljava/lang/Object;", native=False)
    def toArray(self, emu):
        from .array import ObjectArray

        return ObjectArray(list(self.__pyset))

    @java_method_def(name="size", signature="()I", native=False)
    def size(self, emu):
        return len(self.__pyset)
