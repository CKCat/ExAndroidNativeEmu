from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .array import ByteArray
from .object import Object


class String(
    Object, metaclass=JavaClassDef, jvm_name="java/lang/String", jvm_super=Object
):
    def __init__(self, pystr=""):
        Object.__init__(self)
        assert isinstance(pystr, str)
        self.__str = pystr

    def get_py_string(self):
        return self.__str

    def __eq__(self, other):
        if isinstance(other, String):
            return self.__str == other.get_py_string()
        return False

    def __hash__(self):
        return hash(self.__str)

    @java_method_def(
        name="<init>",
        args_list=["jobject", "jstring"],
        signature="([BLjava/lang/String;)V",
        native=False,
    )
    def ctor(self, emu, barr, charset):
        pyarr = barr.get_py_items()
        pystr = charset.get_py_string()
        self.__str = pyarr.decode(pystr)

    @java_method_def(name="hashCode", signature="()I", native=False)
    def hashCode(self, emu):
        h = 0
        for c in self.__str:
            h = (31 * h + ord(c)) & 0xFFFFFFFF
        # Java int is signed 32-bit
        if h > 0x7FFFFFFF:
            h -= 0x100000000
        return h

    @java_method_def(
        name="getBytes",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)[B",
        native=False,
    )
    def getBytes(self, emu, charset):
        pycharset = charset.get_py_string()
        barr = bytearray(self.__str, pycharset)
        arr = ByteArray(barr)
        return arr

    @java_method_def(name="getBytes", signature="()[B", native=False)
    def getBytes_default(self, emu):
        barr = bytearray(self.__str, "utf-8")
        arr = ByteArray(barr)
        return arr

    def __repr__(self):
        return "JavaString(%s)" % self.get_py_string()

    @java_method_def(name="toString", signature="()Ljava/lang/String;", native=False)
    def toString(self, emu):
        return self

    @java_method_def(name="length", signature="()I", native=False)
    def length(self, emu):
        return len(self.__str)

    @java_method_def(
        name="equals",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)Z",
        native=False,
    )
    def equals(self, emu, other):
        if isinstance(other, String):
            return self.__str == other.get_py_string()
        return False

    @java_method_def(name="trim", signature="()Ljava/lang/String;", native=False)
    def trim(self, emu):
        return String(self.__str.strip())

    @java_method_def(
        name="substring",
        args_list=["jint"],
        signature="(I)Ljava/lang/String;",
        native=False,
    )
    def substring(self, emu, begin_index):
        return String(self.__str[begin_index:])

    @java_method_def(
        name="substring",
        args_list=["jint", "jint"],
        signature="(II)Ljava/lang/String;",
        native=False,
    )
    def substring_2(self, emu, begin_index, end_index):
        return String(self.__str[begin_index:end_index])
