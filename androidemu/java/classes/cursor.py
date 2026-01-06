from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String


class Cursor(
    Object, metaclass=JavaClassDef, jvm_name="android/database/Cursor", jvm_super=Object
):
    def __init__(self):
        Object.__init__(self)

    @java_method_def(name="close", signature="()V", native=False)
    def close(self, emu):
        pass

    @java_method_def(name="getString", signature="(I)Ljava/lang/String;", native=False)
    def getString(self, emu, columnIndex):
        raise NotImplementedError()

    @java_method_def(name="moveToFirst", signature="()Z", native=False)
    def moveToFirst(self, emu):
        raise NotImplementedError()

    @java_method_def(
        name="getColumnIndex", signature="(Ljava/lang/String;)I", native=False
    )
    def getColumnIndex(self, emu, columnName):
        raise NotImplementedError()


class MatrixCursor(
    Cursor,
    metaclass=JavaClassDef,
    jvm_name="android/database/MatrixCursor",
    jvm_super=Cursor,
):
    def __init__(self, columns):
        Cursor.__init__(self)
        self.__columns = [
            c.get_py_string() if hasattr(c, "get_py_string") else c for c in columns
        ]
        self.__data = []
        self.__position = -1

    @java_method_def(
        name="<init>",
        args_list=["[Ljava/lang/String;"],
        signature="([Ljava/lang/String;)V",
        native=False,
    )
    def ctor(self, emu, columns):
        self.__columns = columns.get_py_items()
        self.__data = []
        self.__position = -1

    @java_method_def(
        name="addRow",
        args_list=["[Ljava/lang/Object;"],
        signature="([Ljava/lang/Object;)V",
        native=False,
    )
    def addRow(self, emu, columnValues):
        vals = columnValues.get_py_items()
        if len(vals) != len(self.__columns):
            raise ValueError("Row data length mismatch column length")
        self.__data.append(vals)

    @java_method_def(name="moveToFirst", signature="()Z", native=False)
    def moveToFirst(self, emu):
        if not self.__data:
            return False
        self.__position = 0
        return True

    @java_method_def(name="moveToNext", signature="()Z", native=False)
    def moveToNext(self, emu):
        if self.__position < len(self.__data) - 1:
            self.__position += 1
            return True
        return False

    @java_method_def(name="getString", signature="(I)Ljava/lang/String;", native=False)
    def getString(self, emu, columnIndex):
        if self.__position < 0 or self.__position >= len(self.__data):
            raise RuntimeError("Cursor index out of bounds")
        val = self.__data[self.__position][columnIndex]
        # val could be String object or maybe python string
        if isinstance(val, str):
            return String(val)
        return val  # Assume it's already an object if not string? Or should we cast?

    @java_method_def(
        name="getColumnIndex", signature="(Ljava/lang/String;)I", native=False
    )
    def getColumnIndex(self, emu, columnName):
        col = columnName.get_py_string()
        if col in self.__columns:
            return self.__columns.index(col)
        return -1
