from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String
from .array import ObjectArray


from ...const.java_const import JAVA_NULL


class Throwable(
    Object, metaclass=JavaClassDef, jvm_name="java/lang/Throwable", jvm_super=Object
):
    def __init__(self, message=None, cause=None):
        Object.__init__(self)
        if isinstance(message, String):
            self.__message = message.get_py_string()
        else:
            self.__message = message
        self.__cause = cause
        self.__stackTrace = []  # List of StackTraceElement

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        self.__message = None
        self.__cause = None
        self.__fillInStackTrace()

    @java_method_def(
        name="<init>",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def ctor_msg(self, emu, message):
        self.__message = message.get_py_string() if message else None
        self.__cause = None
        self.__fillInStackTrace()

    @java_method_def(
        name="<init>",
        args_list=["jstring", "java/lang/Throwable"],
        signature="(Ljava/lang/String;Ljava/lang/Throwable;)V",
        native=False,
    )
    def ctor_msg_cause(self, emu, message, cause):
        self.__message = message.get_py_string() if message else None
        self.__cause = cause
        self.__fillInStackTrace()

    @java_method_def(
        name="<init>",
        args_list=["java/lang/Throwable"],
        signature="(Ljava/lang/Throwable;)V",
        native=False,
    )
    def ctor_cause(self, emu, cause):
        self.__message = cause.toString(emu).get_py_string() if cause else None
        self.__cause = cause
        self.__fillInStackTrace()

    def __fillInStackTrace(self):
        # Stub: could try to get python stack trace, but for emulation usually we just store empty or manual
        pass

    @java_method_def(name="getMessage", signature="()Ljava/lang/String;", native=False)
    def getMessage(self, emu):
        if self.__message:
            return String(self.__message)
        return JAVA_NULL

    @java_method_def(name="getCause", signature="()Ljava/lang/Throwable;", native=False)
    def getCause(self, emu):
        return self.__cause

    @java_method_def(name="toString", signature="()Ljava/lang/String;", native=False)
    def toString(self, emu):
        cls_name = self.getClass(emu).getName(emu).get_py_string()
        if self.__message:
            return String(f"{cls_name}: {self.__message}")
        return String(cls_name)

    @java_method_def(name="printStackTrace", signature="()V", native=False)
    def printStackTrace(self, emu):
        print(self.toString(emu).get_py_string())
        for ste in self.__stackTrace:
            print(f"\tat {ste.toString(emu).get_py_string()}")
        if self.__cause:
            print("Caused by: ", end="")
            self.__cause.printStackTrace(emu)

    @java_method_def(
        name="getStackTrace", signature="()[Ljava/lang/StackTraceElement;", native=False
    )
    def getStackTrace(self, emu):
        # Return ObjectArray of StackTraceElement
        # We assume Array supports ObjectArray creation with elements
        # NOTE: Array implementation usually takes python list of objects
        pass  # To be implemented, need helper to convert list to ObjectArray properly in python
        # Simple stub returning empty array
        return ObjectArray("java/lang/StackTraceElement", [])

    @java_method_def(
        name="setStackTrace",
        args_list=["[Ljava/lang/StackTraceElement;"],
        signature="([Ljava/lang/StackTraceElement;)V",
        native=False,
    )
    def setStackTrace(self, emu, stackTrace):
        # stackTrace is ObjectArray
        py_items = stackTrace.get_py_items()
        self.__stackTrace = py_items

    @java_method_def(
        name="fillInStackTrace", signature="()Ljava/lang/Throwable;", native=False
    )
    def fillInStackTrace(self, emu):
        self.__fillInStackTrace()
        return self


class Exception(
    Throwable,
    metaclass=JavaClassDef,
    jvm_name="java/lang/Exception",
    jvm_super=Throwable,
):
    def __init__(self, message=None, cause=None):
        Throwable.__init__(self, message, cause)


class RuntimeException(
    Exception,
    metaclass=JavaClassDef,
    jvm_name="java/lang/RuntimeException",
    jvm_super=Exception,
):
    def __init__(self, message=None, cause=None):
        Exception.__init__(self, message, cause)


class NullPointerException(
    RuntimeException,
    metaclass=JavaClassDef,
    jvm_name="java/lang/NullPointerException",
    jvm_super=RuntimeException,
):
    def __init__(self, message=None, cause=None):
        RuntimeException.__init__(self, message, cause)


class NoClassDefFoundError(
    Throwable,  # Error inherits from Throwable
    metaclass=JavaClassDef,
    jvm_name="java/lang/NoClassDefFoundError",
    jvm_super=Throwable,
):
    def __init__(self, message=None, cause=None):
        Throwable.__init__(self, message, cause)
