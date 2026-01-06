from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .stream import OutputStream
from .array import ByteArray
from .string import String


class ByteArrayOutputStream(
    OutputStream,
    metaclass=JavaClassDef,
    jvm_name="java/io/ByteArrayOutputStream",
    jvm_super=OutputStream,
):
    def __init__(self, size=32):
        OutputStream.__init__(self)
        self.__buffer = bytearray()

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        OutputStream.__init__(self)
        self.__buffer = bytearray()

    @java_method_def(name="<init>", args_list=["jint"], signature="(I)V", native=False)
    def ctor_size(self, emu, size):
        OutputStream.__init__(self)
        self.__buffer = bytearray()  # python bytearray handles dynamic resize

    @java_method_def(name="write", args_list=["jint"], signature="(I)V", native=False)
    def write_int(self, emu, b):
        self.__buffer.append(b & 0xFF)

    @java_method_def(name="write", args_list=["[B"], signature="([B)V", native=False)
    def write_bytes(self, emu, b):
        self.__buffer.extend(b.get_py_string())

    @java_method_def(
        name="write",
        args_list=["[B", "jint", "jint"],
        signature="([BII)V",
        native=False,
    )
    def write_bytes_off_len(self, emu, b, off, len_):
        data = b.get_py_string()  # bytes
        chunk = data[off : off + len_]
        self.__buffer.extend(chunk)

    @java_method_def(name="toByteArray", signature="()[B", native=False)
    def toByteArray(self, emu):
        return ByteArray(self.__buffer)

    @java_method_def(name="size", signature="()I", native=False)
    def size(self, emu):
        return len(self.__buffer)

    @java_method_def(name="reset", signature="()V", native=False)
    def reset(self, emu):
        self.__buffer = bytearray()

    @java_method_def(name="toString", signature="()Ljava/lang/String;", native=False)
    def toString(self, emu):
        # Default encoding or utf-8
        try:
            return String(self.__buffer.decode("utf-8"))
        except Exception:
            return String(str(self.__buffer))
