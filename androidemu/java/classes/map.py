from ...const.java_const import JAVA_NULL
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .java_set import Set


from .object import Object


class HashMap(
    Object, metaclass=JavaClassDef, jvm_name="java/util/HashMap", jvm_super=Object
):
    def __init__(self, pydict={}):
        Object.__init__(self)
        self.__pydict = pydict

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        self.__pydict = {}

    @java_method_def(name="<init>", signature="(I)V", native=False)
    def ctor2(self, emu):
        self.__pydict = {}

    def __len__(self):
        return len(self.__pydict)

    def __getitem__(self, key):
        return self.__pydict[key]

    def __setitem__(self, key, value):
        self.__pydict[key] = value

    @java_method_def(
        name="get",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)Ljava/lang/Object;",
        native=False,
    )
    def get(self, emu, key):
        if key in self.__pydict:
            return self.__pydict[key]
        return JAVA_NULL

    @java_method_def(
        name="put",
        args_list=["jobject", "jobject"],
        signature="(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        native=False,
    )
    def put(self, emu, key, value):
        prev = JAVA_NULL
        if key in self.__pydict:
            prev = self.__pydict[key]

        self.__pydict[key] = value
        return prev

    @java_method_def(name="size", signature="()I", native=False)
    def size(self, emu):
        return len(self.__pydict)

    @java_method_def(name="keySet", signature="()Ljava/util/Set;", native=False)
    def keySet(self, emu):
        # Note: subclass function override not fully supported, returning temporary Set.
        jset = Set(set(self.__pydict.keys()))
        return jset

    @java_method_def(
        name="remove",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)Ljava/lang/Object;",
        native=False,
    )
    def remove(self, emu, key):
        if key in self.__pydict:
            val = self.__pydict[key]
            del self.__pydict[key]
            return val
        return JAVA_NULL

    @java_method_def(
        name="containsKey",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)Z",
        native=False,
    )
    def containsKey(self, emu, key):
        return key in self.__pydict

    @java_method_def(name="isEmpty", signature="()Z", native=False)
    def isEmpty(self, emu):
        return len(self.__pydict) == 0
