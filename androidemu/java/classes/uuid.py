from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String
import uuid


class UUID(Object, metaclass=JavaClassDef, jvm_name="java/util/UUID", jvm_super=Object):
    def __init__(self, py_uuid):
        Object.__init__(self)
        self.__uuid = py_uuid

    @staticmethod
    @java_method_def(name="randomUUID", signature="()Ljava/util/UUID;", native=False)
    def randomUUID(emu):
        return UUID(uuid.uuid4())

    @staticmethod
    @java_method_def(
        name="fromString",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/util/UUID;",
        native=False,
    )
    def fromString(emu, name):
        return UUID(uuid.UUID(name.get_py_string()))

    @java_method_def(name="toString", signature="()Ljava/lang/String;", native=False)
    def toString(self, emu):
        return String(str(self.__uuid))
