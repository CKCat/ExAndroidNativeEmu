from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String


class StackTraceElement(
    Object,
    metaclass=JavaClassDef,
    jvm_name="java/lang/StackTraceElement",
    jvm_super=Object,
):
    def __init__(self, declaringClass, methodName, fileName, lineNumber):
        Object.__init__(self)
        self.__declaringClass = declaringClass
        self.__methodName = methodName
        self.__fileName = fileName
        self.__lineNumber = lineNumber

    @java_method_def(
        name="<init>",
        args_list=["jstring", "jstring", "jstring", "jint"],
        signature="(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V",
        native=False,
    )
    def ctor(self, emu, declaringClass, methodName, fileName, lineNumber):
        self.__declaringClass = (
            declaringClass.get_py_string() if declaringClass else None
        )
        self.__methodName = methodName.get_py_string() if methodName else None
        self.__fileName = fileName.get_py_string() if fileName else None
        self.__lineNumber = lineNumber

    @java_method_def(
        name="getClassName", signature="()Ljava/lang/String;", native=False
    )
    def getClassName(self, emu):
        return String(self.__declaringClass)

    @java_method_def(
        name="getMethodName", signature="()Ljava/lang/String;", native=False
    )
    def getMethodName(self, emu):
        return String(self.__methodName)

    @java_method_def(name="getFileName", signature="()Ljava/lang/String;", native=False)
    def getFileName(self, emu):
        return String(self.__fileName)

    @java_method_def(name="getLineNumber", signature="()I", native=False)
    def getLineNumber(self, emu):
        return self.__lineNumber

    @java_method_def(name="toString", signature="()Ljava/lang/String;", native=False)
    def toString(self, emu):
        # Format: "declaringClass.methodName(fileName:lineNumber)"
        # Or if fileName is null: "declaringClass.methodName(Unknown Source)"
        file_part = (
            f"{self.__fileName}:{self.__lineNumber}"
            if self.__fileName
            else "Unknown Source"
        )
        return String(f"{self.__declaringClass}.{self.__methodName}({file_part})")
