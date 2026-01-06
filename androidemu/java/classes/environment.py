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
        path = emu.config.get("external_storage", "/sdcard/")
        return File(path)

    @staticmethod
    @java_method_def(
        name="getDataDirectory",
        signature="()Ljava/io/File;",
        native=False,
    )
    def getDataDirectory(emu):
        return File("/data")

    @staticmethod
    @java_method_def(
        name="getRootDirectory",
        signature="()Ljava/io/File;",
        native=False,
    )
    def getRootDirectory(emu):
        return File("/system")

    @staticmethod
    @java_method_def(
        name="getExternalStorageState",
        signature="()Ljava/lang/String;",
        native=False,
    )
    def getExternalStorageState(emu):
        from .string import String

        return String("mounted")  # MEDIA_MOUNTED

    @staticmethod
    @java_method_def(
        name="getExternalStorageState",
        args_list=["Ljava/io/File;"],
        signature="(Ljava/io/File;)Ljava/lang/String;",
        native=False,
    )
    def getExternalStorageStateFile(emu, file):
        from .string import String

        return String("mounted")
