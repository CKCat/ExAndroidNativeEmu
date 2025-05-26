from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .string import String


class File(metaclass=JavaClassDef, jvm_name="java/io/File"):
    def __init__(self, path):
        assert isinstance(path, str)
        self.__path = path

    @java_method_def(
        name="getPath", signature="()Ljava/lang/String;", native=False
    )
    def getPath(self, emu):
        return String(self.__path)

    @java_method_def(
        name="getAbsolutePath", signature="()Ljava/lang/String;", native=False
    )
    def getAbsolutePath(self, emu):
        # FIXME return abspath...
        return String(self.__path)
