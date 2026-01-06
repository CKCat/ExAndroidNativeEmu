from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object


class Boolean(
    Object, metaclass=JavaClassDef, jvm_name="java/lang/Boolean", jvm_super=Object
):
    def __init__(self, value=False):
        Object.__init__(self)
        self.__value = value

    @java_method_def(name="booleanValue", signature="()Z", native=False)
    def booleanValue(self, emu):
        return self.__value

    def __repr__(self):
        return "%r" % self.__value

    def get_py_value(self):
        return self.__value


class Integer(
    Object, metaclass=JavaClassDef, jvm_name="java/lang/Integer", jvm_super=Object
):
    def __init__(self, value=0):
        Object.__init__(self)
        self.__value = value

    @java_method_def(name="<init>", args_list=["jint"], signature="(I)V", native=False)
    def ctor(self, emu, value):
        self.__value = value

    @java_method_def(name="intValue", signature="()I", native=False)
    def intValue(self, emu):
        return self.__value

    def __repr__(self):
        return "%r" % self.__value

    def get_py_value(self):
        return self.__value


class Long(Object, metaclass=JavaClassDef, jvm_name="java/lang/Long", jvm_super=Object):
    def __init__(self, value=0):
        Object.__init__(self)
        self.__value = value

    @java_method_def(name="<init>", args_list=["jlong"], signature="(J)V", native=False)
    def ctor(self, emu, lvalue):
        self.__value = lvalue

    @java_method_def(name="longValue", signature="()J", native=False)
    def longValue(self, emu):
        return self.__value

    def __repr__(self):
        return "%r" % self.__value

    def get_py_value(self):
        return self.__value


class Float(
    Object, metaclass=JavaClassDef, jvm_name="java/lang/Float", jvm_super=Object
):
    def __init__(self, value=0.0):
        Object.__init__(self)
        self.__value = value

    def __repr__(self):
        return "%r" % self.__value

    def get_py_value(self):
        return self.__value


class Double(
    Object, metaclass=JavaClassDef, jvm_name="java/lang/Double", jvm_super=Object
):
    def __init__(self, value=0.0):
        Object.__init__(self)
        self.__value = value

    @java_method_def(
        name="<init>", args_list=["jdouble"], signature="(D)V", native=False
    )
    def ctor(self, emu, value):
        self.__value = value

    @java_method_def(name="doubleValue", signature="()D", native=False)
    def doubleValue(self, emu):
        return self.__value

    def __repr__(self):
        return "%r" % self.__value

    def get_py_value(self):
        return self.__value
