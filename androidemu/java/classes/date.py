from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String
import time


class Date(Object, metaclass=JavaClassDef, jvm_name="java/util/Date", jvm_super=Object):
    def __init__(self, timestamp_ms=None):
        Object.__init__(self)
        if timestamp_ms is None:
            self.__time = int(time.time() * 1000)
        else:
            self.__time = int(timestamp_ms)

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        self.__time = int(time.time() * 1000)

    @java_method_def(name="<init>", args_list=["jlong"], signature="(J)V", native=False)
    def ctor_long(self, emu, date):
        self.__time = date

    @java_method_def(name="getTime", signature="()J", native=False)
    def getTime(self, emu):
        return self.__time

    @java_method_def(
        name="setTime", args_list=["jlong"], signature="(J)V", native=False
    )
    def setTime(self, emu, time_ms):
        self.__time = time_ms

    @java_method_def(name="toString", signature="()Ljava/lang/String;", native=False)
    def toString(self, emu):
        # Java Date.toString() format: "Tue Jan 01 00:00:00 UTC 1970" (approx)
        # Using simplified ctime style
        t = self.__time / 1000.0
        return String(time.ctime(t))
