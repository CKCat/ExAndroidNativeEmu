from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object


class Array(
    Object, metaclass=JavaClassDef, jvm_name="java/lang/reflect/Array", jvm_super=Object
):
    def __init__(self, pyitems):
        Object.__init__(self)
        self.__pyitems = pyitems

    def get_py_items(self):
        return self.__pyitems

    def __len__(self):
        return len(self.__pyitems)

    def __getitem__(self, index):
        return self.__pyitems[index]

    def __setitem__(self, index, value):
        self.__pyitems[index] = value

    def __repr__(self):
        return "JavaArray(%r)" % self.get_py_items()

    @staticmethod
    @java_method_def(
        name="set",
        args_list=["jobject", "jint", "jobject"],
        signature="(Ljava/lang/Object;ILjava/lang/Object;)V",
        native=False,
    )
    def set(emu, array_obj, index, value):
        array_obj[index] = value

    @staticmethod
    @java_method_def(
        name="getLength",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)I",
        native=False,
    )
    def getLength(emu, array_obj):
        # array_obj should be an Array instance or python array wrapper
        return len(array_obj)


# 外面用到，因为与Array jvm name不同，所以暂时手动定义，与Array作用一样
class ByteArray(Array, metaclass=JavaClassDef, jvm_name="[B", jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)

    def get_py_string(self):
        # Helper to get bytes
        # Access parent private member via mangling
        items = self._Array__pyitems
        if isinstance(items, (bytes, bytearray)):
            return bytes(items)
        else:
            # Assume list of ints, handle signed conversion
            return bytes([x & 0xFF for x in items])


# 外面用到，因为与Array jvm name不同，所以暂时手动定义，与Array作用一样
class ObjectArray(
    Array,
    metaclass=JavaClassDef,
    jvm_name="[Ljava/lang/Object;",
    jvm_super=Array,
):
    def __init__(self, item_list):
        Array.__init__(self, item_list)


class ClassArray(
    Array,
    metaclass=JavaClassDef,
    jvm_name="[Ljava/lang/Class;",
    jvm_super=Array,
):
    def __init__(self, item_list):
        Array.__init__(self, item_list)


class StringArray(
    Array,
    metaclass=JavaClassDef,
    jvm_name="[Ljava/lang/String;",
    jvm_super=Array,
):
    def __init__(self, item_list):
        Array.__init__(self, item_list)


class BooleanArray(Array, metaclass=JavaClassDef, jvm_name="[Z", jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)


class CharArray(Array, metaclass=JavaClassDef, jvm_name="[C", jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)


class ShortArray(Array, metaclass=JavaClassDef, jvm_name="[S", jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)


class IntArray(Array, metaclass=JavaClassDef, jvm_name="[I", jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)


class LongArray(Array, metaclass=JavaClassDef, jvm_name="[J", jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)


class FloatArray(Array, metaclass=JavaClassDef, jvm_name="[F", jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)


class DoubleArray(Array, metaclass=JavaClassDef, jvm_name="[D", jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)
