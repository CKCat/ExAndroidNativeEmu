from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String


class InetAddress(
    Object, metaclass=JavaClassDef, jvm_name="java/net/InetAddress", jvm_super=Object
):
    def __init__(self, host, ip):
        Object.__init__(self)
        self.__host = host
        self.__ip = ip

    @staticmethod
    @java_method_def(
        name="getByName",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/net/InetAddress;",
        native=False,
    )
    def getByName(emu, host_str):
        # Stub: just return what passed
        h = host_str.get_py_string()
        # Resolve 'localhost' or others if we want
        return InetAddress(h, "127.0.0.1")

    @java_method_def(name="getHostName", signature="()Ljava/lang/String;", native=False)
    def getHostName(self, emu):
        return String(self.__host)

    @java_method_def(
        name="getHostAddress", signature="()Ljava/lang/String;", native=False
    )
    def getHostAddress(self, emu):
        return String(self.__ip)
