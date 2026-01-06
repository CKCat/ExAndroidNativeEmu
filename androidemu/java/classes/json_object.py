from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String
import json


class JSONObject(
    Object, metaclass=JavaClassDef, jvm_name="org/json/JSONObject", jvm_super=Object
):
    def __init__(self, json_str_or_dict="{}"):
        Object.__init__(self)
        if isinstance(json_str_or_dict, dict):
            self.__data = json_str_or_dict
        elif isinstance(json_str_or_dict, str):
            try:
                self.__data = json.loads(json_str_or_dict)
            except Exception:
                self.__data = {}
        else:
            self.__data = {}

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        self.__data = {}

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
            # throw JSONException ideally
            self.__data = {}

    @java_method_def(
        name="put",
        args_list=["jstring", "jint"],
        signature="(Ljava/lang/String;I)Lorg/json/JSONObject;",
        native=False,
    )
    def put_int(self, emu, key, value):
        self.__data[key.get_py_string()] = value
        return self

    @java_method_def(
        name="put",
        args_list=["jstring", "jboolean"],
        signature="(Ljava/lang/String;Z)Lorg/json/JSONObject;",
        native=False,
    )
    def put_bool(self, emu, key, value):
        self.__data[key.get_py_string()] = value
        return self

    @java_method_def(
        name="put",
        args_list=["jstring", "jlong"],
        signature="(Ljava/lang/String;J)Lorg/json/JSONObject;",
        native=False,
    )
    def put_long(self, emu, key, value):
        self.__data[key.get_py_string()] = value
        return self

    @java_method_def(
        name="put",
        args_list=["jstring", "jdouble"],
        signature="(Ljava/lang/String;D)Lorg/json/JSONObject;",
        native=False,
    )
    def put_double(self, emu, key, value):
        self.__data[key.get_py_string()] = value
        return self

    @java_method_def(
        name="put",
        args_list=["jstring", "jobject"],
        signature="(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;",
        native=False,
    )
    def put_obj(self, emu, key, value):
        from .json_array import JSONArray

        py_key = key.get_py_string()
        if isinstance(value, String):
            self.__data[py_key] = value.get_py_string()
        elif hasattr(value, "get_py_value"):
            self.__data[py_key] = value.get_py_value()
        elif isinstance(value, (JSONObject, JSONArray)):
            self.__data[py_key] = value
        elif isinstance(value, list):
            self.__data[py_key] = JSONArray(value)
        elif isinstance(value, dict):
            self.__data[py_key] = JSONObject(value)
        else:
            self.__data[py_key] = value
        return self

    @java_method_def(
        name="getString",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/String;",
        native=False,
    )
    def getString(self, emu, key):
        val = self.__data[key.get_py_string()]
        return String(str(val))

    @java_method_def(
        name="optString",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/String;",
        native=False,
    )
    def optString(self, emu, key):
        py_key = key.get_py_string()
        val = self.__data.get(py_key, "")
        return String(str(val))

    @java_method_def(
        name="optString",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        native=False,
    )
    def optStringDef(self, emu, key, default):
        py_key = key.get_py_string()
        val = self.__data.get(py_key, default.get_py_string())
        return String(str(val))

    @java_method_def(
        name="getInt",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)I",
        native=False,
    )
    def getInt(self, emu, key):
        return int(self.__data[key.get_py_string()])

    @java_method_def(
        name="optInt",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)I",
        native=False,
    )
    def optInt(self, emu, key):
        return int(self.__data.get(key.get_py_string(), 0))

    @java_method_def(
        name="getBoolean",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Z",
        native=False,
    )
    def getBoolean(self, emu, key):
        return bool(self.__data[key.get_py_string()])

    @java_method_def(
        name="optBoolean",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Z",
        native=False,
    )
    def optBoolean(self, emu, key):
        return bool(self.__data.get(key.get_py_string(), False))

    @java_method_def(
        name="has",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Z",
        native=False,
    )
    def has(self, emu, key):
        return key.get_py_string() in self.__data

    @java_method_def(name="toString", signature="()Ljava/lang/String;", native=False)
    def toString(self, emu):
        return String(json.dumps(self.to_python_structure()))

    def __str__(self):
        return json.dumps(self.to_python_structure())

    def to_python_structure(self):
        out = {}
        for k, v in self.__data.items():
            if hasattr(v, "to_python_structure"):
                out[k] = v.to_python_structure()
            elif hasattr(v, "get_py_value"):
                out[k] = v.get_py_value()
            elif hasattr(v, "get_py_string"):
                out[k] = v.get_py_string()
            else:
                out[k] = v
        return out
