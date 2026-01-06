from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from ...const.java_const import JAVA_NULL
from .array import ByteArray


class InputStream(metaclass=JavaClassDef, jvm_name="java/io/InputStream"):
    def __init__(self, py_file_obj=None, data=None):
        self.__file = py_file_obj
        self.__data = data
        self.__pos = 0

    @java_method_def(name="read", signature="()I", native=False)
    def read(self, emu):
        if self.__file:
            b = self.__file.read(1)
            if not b:
                return -1
            return b[0]
        elif self.__data:
            if self.__pos < len(self.__data):
                b = self.__data[self.__pos]
                self.__pos += 1
                return b
            return -1
        return -1

    @java_method_def(name="read", args_list=["[B"], signature="([B)I", native=False)
    def read_bytes(self, emu, dest_arr):
        if self.__file:
            # We don't know the size directly from dest_arr wrapper usually,
            # unless we access it. dest_arr is a ByteArray instance.
            # Assuming dest_arr has a defined length.
            length = len(dest_arr)
            data = self.__file.read(length)
            if not data:
                return -1

            # Copy data to dest_arr
            # This is slow, but functional for emulation
            for i, b in enumerate(data):
                dest_arr[i] = b
            return len(data)

        elif self.__data:
            length = len(dest_arr)
            available = len(self.__data) - self.__pos
            if available <= 0:
                return -1

            to_read = min(length, available)
            data = self.__data[self.__pos : self.__pos + to_read]
            self.__pos += to_read

            for i, b in enumerate(data):
                dest_arr[i] = b
            return to_read

        return -1

    @java_method_def(name="close", signature="()V", native=False)
    def close(self, emu):
        if self.__file:
            self.__file.close()

    @java_method_def(name="available", signature="()I", native=False)
    def available(self, emu):
        if self.__data:
            return len(self.__data) - self.__pos
        # for file, it's hard to know without seeking end, which might not be supported
        return 0


class OutputStream(metaclass=JavaClassDef, jvm_name="java/io/OutputStream"):
    def __init__(self, py_file_obj=None):
        self.__file = py_file_obj

    @java_method_def(name="write", args_list=["[B"], signature="([B)V", native=False)
    def write_bytes(self, emu, data):
        if self.__file:
            # data is ByteArray
            self.__file.write(bytes(data))

    @java_method_def(
        name="write",
        args_list=["[B", "jint", "jint"],
        signature="([BII)V",
        native=False,
    )
    def write_bytes_off_len(self, emu, data, off, len_):
        if self.__file:
            b_data = bytes(data)
            self.__file.write(b_data[off : off + len_])

    @java_method_def(name="write", args_list=["jint"], signature="(I)V", native=False)
    def write_int(self, emu, data):
        if self.__file:
            self.__file.write(bytes([data & 0xFF]))

    @java_method_def(name="flush", signature="()V", native=False)
    def flush(self, emu):
        if self.__file:
            self.__file.flush()

    @java_method_def(name="close", signature="()V", native=False)
    def close(self, emu):
        if self.__file:
            self.__file.close()
