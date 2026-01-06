from ...const.java_const import JAVA_NULL
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .string import String


class Bundle(metaclass=JavaClassDef, jvm_name="android/os/Bundle"):
    def __init__(self, py_map={}):
        self.__pymap = py_map

    @java_method_def(
        name="putString",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)V",
        native=False,
    )
    def putString(self, emu, k, v):
        self.__pymap[k.get_py_string()] = v.get_py_string()

    @java_method_def(
        name="putInt",
        args_list=["jstring", "jint"],
        signature="(Ljava/lang/String;I)V",
        native=False,
    )
    def putInt(self, emu, k, v):
        self.__pymap[k.get_py_string()] = v

    @java_method_def(
        name="putLong",
        args_list=["jstring", "jlong"],
        signature="(Ljava/lang/String;J)V",
        native=False,
    )
    def putLong(self, emu, k, v):
        self.__pymap[k.get_py_string()] = v

    @java_method_def(
        name="putBoolean",
        args_list=["jstring", "jboolean"],
        signature="(Ljava/lang/String;Z)V",
        native=False,
    )
    def putBoolean(self, emu, k, v):
        self.__pymap[k.get_py_string()] = v

    @java_method_def(
        name="getBoolean",
        args_list=["jstring", "jboolean"],
        signature="(Ljava/lang/String;Z)Z",
        native=False,
    )
    def getBoolean_def(self, emu, k, default_val):
        pykey = k.get_py_string()
        return self.__pymap.get(pykey, default_val)

    @java_method_def(
        name="getInt",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)I",
        native=False,
    )
    def getInt(self, emu, k):
        return self.__pymap.get(k.get_py_string(), 0)

    @java_method_def(
        name="getString",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/String;",
        native=False,
    )
    def getString(self, emu, k):
        pykey = k.get_py_string()
        if pykey in self.__pymap:
            return String(str(self.__pymap[pykey]))  # Ensure string return
        else:
            # return null
            return JAVA_NULL

    @java_method_def(
        name="getBoolean",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Z",
        native=False,
    )
    def getBoolean(self, emu, k):
        pykey = k.get_py_string()
        if pykey in self.__pymap:
            return bool(self.__pymap[pykey])
        else:
            return False  # default false for boolean primitive return
