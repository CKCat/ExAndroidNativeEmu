from ..classes.file import File
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def


class Environment(metaclass=JavaClassDef, jvm_name="android/os/Environment"):
    def __init__(self):
        pass

    @staticmethod
    @java_method_def(
        name="getExternalStorageDirectory",
        signature="()Ljava/io/File;",
        native=False,
    )
    def getExternalStorageDirectory(emu):
        return File("/sdcard/")
