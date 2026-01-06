from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String
from .date import Date
from datetime import datetime


import re


class SimpleDateFormat(
    Object,
    metaclass=JavaClassDef,
    jvm_name="java/text/SimpleDateFormat",
    jvm_super=Object,
):
    def __init__(self, pattern=None):
        Object.__init__(self)
        self.__pattern = pattern
        self.__py_fmt = self.__convert_pattern(pattern) if pattern else ""

    def __convert_pattern(self, pattern):
        def repl(match):
            m = match.group(0)
            if m == "yyyy":
                return "%Y"
            if m == "yy":
                return "%y"
            if m == "MM" or m == "M":
                return "%m"
            if m == "dd" or m == "d":
                return "%d"
            if m == "HH" or m == "H":
                return "%H"
            if m == "mm" or m == "m":
                return "%M"
            if m == "ss" or m == "s":
                return "%S"
            return m

        # Match longest first
        regex = r"yyyy|yy|MM|M|dd|d|HH|H|mm|m|ss|s"
        return re.sub(regex, repl, pattern)

    @java_method_def(
        name="<init>",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def ctor(self, emu, pattern):
        self.__pattern = pattern.get_py_string()
        self.__py_fmt = self.__convert_pattern(self.__pattern)

    @java_method_def(
        name="format",
        args_list=["java/util/Date"],
        signature="(Ljava/util/Date;)Ljava/lang/String;",
        native=False,
    )
    def format(self, emu, date):
        ts = date.getTime(emu) / 1000.0
        # Uses local system time. Full timezone support would require additional libraries (e.g. pytz).
        dt = datetime.fromtimestamp(ts)
        return String(dt.strftime(self.__py_fmt))

    @java_method_def(
        name="parse",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/util/Date;",
        native=False,
    )
    def parse(self, emu, source):
        src = source.get_py_string()
        try:
            dt = datetime.strptime(src, self.__py_fmt)
            ts_ms = int(dt.timestamp() * 1000)
            return Date(ts_ms)
        except Exception:
            # ParseException
            return Date(0)
