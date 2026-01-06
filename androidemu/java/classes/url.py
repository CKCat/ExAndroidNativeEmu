from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String
from .url_connection import URLConnection
import urllib.parse


class URL(Object, metaclass=JavaClassDef, jvm_name="java/net/URL", jvm_super=Object):
    def __init__(self, spec=None):
        Object.__init__(self)
        self.__spec = spec
        if spec:
            if isinstance(spec, String):
                self.__spec = spec.get_py_string()
            self.__parse(self.__spec)

    def __parse(self, spec):
        self.__parsed = urllib.parse.urlparse(spec)
        self.__protocol = self.__parsed.scheme
        self.__host = self.__parsed.hostname
        self.__port = self.__parsed.port if self.__parsed.port else -1
        self.__file = self.__parsed.path + (
            "?" + self.__parsed.query if self.__parsed.query else ""
        )

    @java_method_def(
        name="<init>",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def ctor(self, emu, spec):
        self.__spec = spec.get_py_string()
        self.__parse(self.__spec)

    @java_method_def(
        name="openConnection", signature="()Ljava/net/URLConnection;", native=False
    )
    def openConnection(self, emu):
        return URLConnection(self)

    @java_method_def(name="toString", signature="()Ljava/lang/String;", native=False)
    def toString(self, emu):
        return String(self.__spec)

    @java_method_def(name="getProtocol", signature="()Ljava/lang/String;", native=False)
    def getProtocol(self, emu):
        return String(self.__protocol)

    @java_method_def(name="getHost", signature="()Ljava/lang/String;", native=False)
    def getHost(self, emu):
        return String(self.__host)

    @java_method_def(name="getPath", signature="()Ljava/lang/String;", native=False)
    def getPath(self, emu):
        return String(self.__parsed.path)

    @java_method_def(name="getFile", signature="()Ljava/lang/String;", native=False)
    def getFile(self, emu):
        return String(self.__file)

    @java_method_def(name="getPort", signature="()I", native=False)
    def getPort(self, emu):
        return self.__port

    @java_method_def(name="getQuery", signature="()Ljava/lang/String;", native=False)
    def getQuery(self, emu):
        return String(self.__parsed.query) if self.__parsed.query else None

    @java_method_def(name="getRef", signature="()Ljava/lang/String;", native=False)
    def getRef(self, emu):
        return String(self.__parsed.fragment) if self.__parsed.fragment else None
