from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String


class StringBuilder(
    Object, metaclass=JavaClassDef, jvm_name="java/lang/StringBuilder", jvm_super=Object
):
    def __init__(self, char_seq=None):
        Object.__init__(self)
        self.__str = ""
        if char_seq:
            # char_seq could be String or another StringBuilder or python string
            if hasattr(char_seq, "get_py_string"):
                self.__str = char_seq.get_py_string()
            elif isinstance(char_seq, str):
                self.__str = char_seq

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        pass

    @java_method_def(
        name="<init>",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def ctor_string(self, emu, s):
        self.__str = s.get_py_string()

    @java_method_def(
        name="append",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/StringBuilder;",
        native=False,
    )
    def append_string(self, emu, s):
        if s:  # s could be None (Java null) which appends "null"
            self.__str += s.get_py_string()
        else:
            self.__str += "null"
        return self

    @java_method_def(
        name="append",
        args_list=["I"],
        signature="(I)Ljava/lang/StringBuilder;",
        native=False,
    )
    def append_int(self, emu, val):
        self.__str += str(val)
        return self

    @java_method_def(name="toString", signature="()Ljava/lang/String;", native=False)
    def toString(self, emu):
        return String(self.__str)
