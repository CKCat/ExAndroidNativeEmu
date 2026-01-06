from ...const.java_const import JAVA_NULL
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def


from .object import Object


class List(Object, metaclass=JavaClassDef, jvm_name="java/util/List", jvm_super=Object):
    def __init__(self, pylist):
        Object.__init__(self)
        self.__pylist = pylist

    def __len__(self):
        return len(self.__pylist)

    def __getitem__(self, index):
        return self.__pylist[index]

    def __setitem__(self, index, value):
        self.__pylist[index] = value

    @java_method_def(
        name="get",
        args_list=["jint"],
        signature="(I)Ljava/lang/Object;",
        native=False,
    )
    def get(self, emu, index):
        if index < len(self.__pylist):
            return self.__pylist[index]
        return JAVA_NULL

    @java_method_def(name="size", signature="()I", native=False)
    def size(self, emu):
        return len(self.__pylist)

    @java_method_def(
        name="add",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)Z",
        native=False,
    )
    def add(self, emu, item):
        self.__pylist.append(item)
        return True

    @java_method_def(
        name="remove",
        args_list=["jint"],
        signature="(I)Ljava/lang/Object;",
        native=False,
    )
    def remove(self, emu, index):
        if 0 <= index < len(self.__pylist):
            return self.__pylist.pop(index)
        # Should throw IndexOutOfBoundsException
        return JAVA_NULL

    @java_method_def(
        name="remove",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)Z",
        native=False,
    )
    def remove_obj(self, emu, item):
        # Native python remove compares by equality (calls __eq__)
        # This matches Java behavior where list.remove(Object) uses equals()
        try:
            self.__pylist.remove(item)
            return True
        except ValueError:
            return False

    @java_method_def(name="iterator", signature="()Ljava/util/Iterator;", native=False)
    def iterator(self, emu):
        from .iterator import Iterator

        return Iterator(self.__pylist)

    @java_method_def(name="toArray", signature="()[Ljava/lang/Object;", native=False)
    def toArray(self, emu):
        from .array import ObjectArray

        return ObjectArray(self.__pylist)

    @java_method_def(name="isEmpty", signature="()Z", native=False)
    def isEmpty(self, emu):
        return len(self.__pylist) == 0

    @java_method_def(
        name="contains",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)Z",
        native=False,
    )
    def contains(self, emu, item):
        return item in self.__pylist

    @java_method_def(name="clear", signature="()V", native=False)
    def clear(self, emu):
        self.__pylist.clear()

    @java_method_def(
        name="indexOf",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)I",
        native=False,
    )
    def indexOf(self, emu, item):
        try:
            return self.__pylist.index(item)
        except ValueError:
            return -1


class ArrayList(
    List, metaclass=JavaClassDef, jvm_name="java/util/ArrayList", jvm_super=List
):
    def __init__(self, pylist=None):
        if pylist is None:
            pylist = []
        List.__init__(self, pylist)

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        List.__init__(self, [])

    @java_method_def(name="<init>", args_list=["I"], signature="(I)V", native=False)
    def ctor_capacity(self, emu, capacity):
        List.__init__(self, [])

    @java_method_def(
        name="<init>",
        args_list=["Ljava/util/Collection;"],
        signature="(Ljava/util/Collection;)V",
        native=False,
    )
    def ctor_collection(self, emu, collection):
        # copy items
        # assuming collection has iterator or we can access internal list if it's our implementation
        # For now assume it's one of our Lists
        if hasattr(collection, "_List__pylist"):
            # access private attribute of List? name mangling makes it _List__pylist
            List.__init__(self, list(collection._List__pylist))
        else:
            List.__init__(self, [])
