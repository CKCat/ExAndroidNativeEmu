import zipfile

from ...utils import misc_utils
from ..java_class_def import JavaClassDef


class AssetManager(
    metaclass=JavaClassDef, jvm_name="android/content/res/AssetManager"
):
    def __init__(self, emu, pyapk_path):
        self.__py_apk_path = pyapk_path
        vfs_root = emu.get_vfs_root()
        real_apk_path = misc_utils.vfs_path_to_system_path(vfs_root, pyapk_path)
        self.__zip_file = zipfile.ZipFile(real_apk_path, "r")

    def get_zip_file(self):
        return self.__zip_file
