from urllib.parse import urlparse, parse_qs
from .string import String
from .object import Object
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from ...const.java_const import JAVA_NULL


class Uri(Object, metaclass=JavaClassDef, jvm_name="android/net/Uri", jvm_super=Object):
    def __init__(self, pystr):
        Object.__init__(self)
        self.__uri = pystr
        self.__parsed = urlparse(pystr)

    def get_py_string(self):
        return self.__uri

    def __repr__(self):
        return "Uri(%s)" % self.__uri

    @staticmethod
    @java_method_def(
        name="parse",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Landroid/net/Uri;",
        native=False,
    )
    def parse(emu, uri):
        pystr_uri = uri.get_py_string()
        uri = Uri(pystr_uri)
        return uri

    @java_method_def(name="getScheme", signature="()Ljava/lang/String;", native=False)
    def getScheme(self, emu):
        return String(self.__parsed.scheme) if self.__parsed.scheme else JAVA_NULL

    @java_method_def(name="getHost", signature="()Ljava/lang/String;", native=False)
    def getHost(self, emu):
        return String(self.__parsed.hostname) if self.__parsed.hostname else JAVA_NULL

    @java_method_def(name="getPath", signature="()Ljava/lang/String;", native=False)
    def getPath(self, emu):
        return String(self.__parsed.path) if self.__parsed.path else JAVA_NULL

    @java_method_def(
        name="getQueryParameter",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/String;",
        native=False,
    )
    def getQueryParameter(self, emu, key):
        if not self.__parsed.query:
            return JAVA_NULL
        qs = parse_qs(self.__parsed.query)
        py_key = key.get_py_string()
        if py_key in qs:
            return String(qs[py_key][0])  # Return first match
        return JAVA_NULL

    @java_method_def(name="toString", signature="()Ljava/lang/String;", native=False)
    def toString(self, emu):
        return String(self.__uri)

    @java_method_def(
        name="equals",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)Z",
        native=False,
    )
    def equals(self, emu, other):
        if isinstance(other, Uri):
            return self.__uri == other.get_py_string()
        return False

    @java_method_def(name="hashCode", signature="()I", native=False)
    def hashCode(self, emu):
        return hash(self.__uri)
