from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String
from .types import Integer, Boolean, Long, Float, Double
import json
from .json_object import JSONObject


class JSONArray(
    Object, metaclass=JavaClassDef, jvm_name="org/json/JSONArray", jvm_super=Object
):
    def __init__(self, json_str_or_list="[]"):
        Object.__init__(self)
        if isinstance(json_str_or_list, list):
            self.__data = json_str_or_list
        elif isinstance(json_str_or_list, str):
            try:
                self.__data = json.loads(json_str_or_list)
            except Exception:
                self.__data = []
        else:
            self.__data = []

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        self.__data = []

    @java_method_def(
        name="<init>",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def ctor_str(self, emu, json_str):
        py_str = json_str.get_py_string()
        try:
            self.__data = json.loads(py_str)
        except Exception:
            self.__data = []

    @java_method_def(name="length", signature="()I", native=False)
    def length(self, emu):
        return len(self.__data)

    @java_method_def(
        name="put",
        args_list=["jint"],
        signature="(I)Lorg/json/JSONArray;",
        native=False,
    )
    def put_int(self, emu, value):
        self.__data.append(value)
        return self

    @java_method_def(
        name="put",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)Lorg/json/JSONArray;",
        native=False,
    )
    def put_obj(self, emu, value):
        if isinstance(value, String):
            self.__data.append(value.get_py_string())
        else:
            self.__data.append(value)
        return self

    @java_method_def(
        name="getString",
        args_list=["jint"],
        signature="(I)Ljava/lang/String;",
        native=False,
    )
    def getString(self, emu, index):
        if 0 <= index < len(self.__data):
            return String(str(self.__data[index]))
        # throw
        return String("")

    @java_method_def(
        name="optString",
        args_list=["jint"],
        signature="(I)Ljava/lang/String;",
        native=False,
    )
    def optString(self, emu, index):
        if 0 <= index < len(self.__data):
            return String(str(self.__data[index]))
        return String("")

    @java_method_def(name="getInt", args_list=["jint"], signature="(I)I", native=False)
    def getInt(self, emu, index):
        return int(self.__data[index])

    @java_method_def(name="optInt", args_list=["jint"], signature="(I)I", native=False)
    def optInt(self, emu, index):
        if 0 <= index < len(self.__data):
            return int(self.__data[index])
        return 0

    @java_method_def(
        name="get", args_list=["jint"], signature="(I)Ljava/lang/Object;", native=False
    )
    def get(self, emu, index):
        # Return object if possible.
        # If string, return String.
        # If int, return Integer (not implemented as wrapper here, just int?)
        # Wait, signature returns Object.
        # We should wrap basic types if needed but our emulator might handle int->Integer conversion automatically?
        # No, JavaMethodDef expects Object.
        val = self.__data[index]
        if isinstance(val, Object):
            return val
        if isinstance(val, bool):
            return Boolean(val)
        elif isinstance(val, int):
            return Integer(val)
        elif isinstance(val, float):
            return Double(val)
        elif isinstance(val, str):
            return String(val)
        elif isinstance(val, dict):
            from .json_object import JSONObject

            return JSONObject(val)
        elif isinstance(val, list):
            # Use current class for array
            return JSONArray(val)
        else:
            return String(str(val))

    @java_method_def(name="toString", signature="()Ljava/lang/String;", native=False)
    def toString(self, emu):
        return String(json.dumps(self.to_python_structure()))

    def __str__(self):
        return json.dumps(self.to_python_structure())

    def to_python_structure(self):
        out = []
        for v in self.__data:
            if hasattr(v, "to_python_structure"):
                out.append(v.to_python_structure())
            elif hasattr(v, "get_py_value"):
                out.append(v.get_py_value())
            elif hasattr(v, "get_py_string"):
                out.append(v.get_py_string())
            else:
                out.append(v)
        return out
