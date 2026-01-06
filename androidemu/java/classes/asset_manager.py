import zipfile

from ...utils import misc_utils
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from ...const.java_const import JAVA_NULL
from loguru import logger


class AssetManager(metaclass=JavaClassDef, jvm_name="android/content/res/AssetManager"):
    def __init__(self, emu, pyapk_path):
        self.__py_apk_path = pyapk_path
        vfs_root = emu.get_vfs_root()
        real_apk_path = misc_utils.vfs_path_to_system_path(vfs_root, pyapk_path)
        self.__zip_file = zipfile.ZipFile(real_apk_path, "r")

    @java_method_def(
        name="open",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/io/InputStream;",
        native=False,
    )
    def open(self, emu, filename):
        py_filename = filename.get_py_string()
        try:
            # zipfile.open returns a file-like object
            f = self.__zip_file.open(py_filename)
            from .stream import InputStream

            return InputStream(py_file_obj=f)
        except Exception as e:
            # FileNotFoundException
            logger.warning(f"AssetManager: file not found {py_filename}")
            return JAVA_NULL

    @java_method_def(
        name="list",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)[Ljava/lang/String;",
        native=False,
    )
    def list(self, emu, path):
        py_path = path.get_py_string()
        # Ensure path ends with slash if not empty
        prefix = py_path
        if prefix and not prefix.endswith("/"):
            prefix += "/"

        # ZipFile namelist returns all files
        all_files = self.__zip_file.namelist()
        results = set()

        for f in all_files:
            if f.startswith(prefix):
                # Get the immediate child
                # e.g. path="assets/", f="assets/sub/file" -> "sub"
                # Strip prefix
                suffix = f[len(prefix) :]
                # Split by slash
                parts = suffix.split("/")
                if parts[0]:
                    results.add(parts[0])

        from .string import String
        from .array import StringArray

        # Wrap python strings in Java String objects
        java_results = [String(s) for s in results]
        return StringArray(java_results)

    @java_method_def(name="close", signature="()V", native=False)
    def close(self, emu):
        self.__zip_file.close()

    def get_zip_file(self):
        return self.__zip_file
