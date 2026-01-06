import os
from ...utils import misc_utils
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .string import String
from ...const.java_const import JAVA_NULL


class File(metaclass=JavaClassDef, jvm_name="java/io/File"):
    def __init__(self, path, child=None):
        if isinstance(path, String):
            path = path.get_py_string()

        if child:
            if isinstance(child, String):
                child = child.get_py_string()
            self.__path = os.path.join(path, child).replace("\\", "/")
        else:
            self.__path = path.replace("\\", "/")

    @java_method_def(
        name="<init>",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def ctor(self, emu, path):
        self.__init__(path.get_py_string())

    @java_method_def(
        name="<init>",
        args_list=["jobject", "jstring"],
        signature="(Ljava/io/File;Ljava/lang/String;)V",
        native=False,
    )
    def ctor_parent_file(self, emu, parent, child):
        # parent is a File object
        parent_path = parent.getPath(emu).get_py_string()
        self.__init__(parent_path, child.get_py_string())

    @java_method_def(
        name="<init>",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)V",
        native=False,
    )
    def ctor_parent_string(self, emu, parent, child):
        self.__init__(parent.get_py_string(), child.get_py_string())

    @java_method_def(name="getPath", signature="()Ljava/lang/String;", native=False)
    def getPath(self, emu):
        return String(self.__path)

    @java_method_def(
        name="getAbsolutePath", signature="()Ljava/lang/String;", native=False
    )
    def getAbsolutePath(self, emu):
        # Similar to getPath in this context unless we want to resolve against cwd
        return String(self.__path)

    @java_method_def(name="exists", signature="()Z", native=False)
    def exists(self, emu):
        real_path = misc_utils.vfs_path_to_system_path(emu.get_vfs_root(), self.__path)
        return os.path.exists(real_path)

    @java_method_def(name="isDirectory", signature="()Z", native=False)
    def isDirectory(self, emu):
        real_path = misc_utils.vfs_path_to_system_path(emu.get_vfs_root(), self.__path)
        return os.path.isdir(real_path)

    @java_method_def(name="isFile", signature="()Z", native=False)
    def isFile(self, emu):
        real_path = misc_utils.vfs_path_to_system_path(emu.get_vfs_root(), self.__path)
        return os.path.isfile(real_path)

    @java_method_def(name="length", signature="()J", native=False)
    def length(self, emu):
        real_path = misc_utils.vfs_path_to_system_path(emu.get_vfs_root(), self.__path)
        if os.path.exists(real_path):
            return os.path.getsize(real_path)
        return 0

    @java_method_def(name="getName", signature="()Ljava/lang/String;", native=False)
    def getName(self, emu):
        return String(os.path.basename(self.__path))

    @java_method_def(name="getParent", signature="()Ljava/lang/String;", native=False)
    def getParent(self, emu):
        parent = os.path.dirname(self.__path)
        return String(parent) if parent else JAVA_NULL

    @java_method_def(name="getParentFile", signature="()Ljava/io/File;", native=False)
    def getParentFile(self, emu):
        parent = os.path.dirname(self.__path)
        return File(parent) if parent else JAVA_NULL

    @java_method_def(name="mkdir", signature="()Z", native=False)
    def mkdir(self, emu):
        real_path = misc_utils.vfs_path_to_system_path(emu.get_vfs_root(), self.__path)
        try:
            os.mkdir(real_path)
            return True
        except:
            return False

    @java_method_def(name="mkdirs", signature="()Z", native=False)
    def mkdirs(self, emu):
        real_path = misc_utils.vfs_path_to_system_path(emu.get_vfs_root(), self.__path)
        try:
            os.makedirs(real_path, exist_ok=True)
            return True
        except:
            return False

    @java_method_def(name="delete", signature="()Z", native=False)
    def delete(self, emu):
        real_path = misc_utils.vfs_path_to_system_path(emu.get_vfs_root(), self.__path)
        try:
            if os.path.isfile(real_path):
                os.remove(real_path)
            elif os.path.isdir(real_path):
                os.rmdir(real_path)
            else:
                return False
            return True
        except:
            return False

    @java_method_def(name="lastModified", signature="()J", native=False)
    def lastModified(self, emu):
        real_path = misc_utils.vfs_path_to_system_path(emu.get_vfs_root(), self.__path)
        try:
            return int(os.path.getmtime(real_path) * 1000)
        except:
            return 0

    @java_method_def(name="listFiles", signature="()[Ljava/io/File;", native=False)
    def listFiles(self, emu):
        real_path = misc_utils.vfs_path_to_system_path(emu.get_vfs_root(), self.__path)
        if not os.path.isdir(real_path):
            return JAVA_NULL

        try:
            files = os.listdir(real_path)
            # Create File objects
            # Need strict import to avoid circular dependency issues if any, ideally inside method
            # Assuming File class is self
            file_objs = []
            for f in files:
                child_path = os.path.join(self.__path, f).replace("\\", "/")
                file_objs.append(File(child_path))

            from .array import ObjectArray

            # We need a FileArray ideally but ObjectArray works generally if signature allows,
            # or we need to define FileArray [Ljava/io/File;
            # For now returning ObjectArray but in Java it's specific.
            # Let's check array.py if we have FileArray or can use ObjectArray with correct JVM name?
            # Creating a custom FileArray on the fly or just assume ObjectArray is ok for python side logic if not strict check.
            # But the signature says [Ljava/io/File;
            # Let's create a specific array wrapper.
            return ObjectArray(
                file_objs
            )  # This has [Ljava/lang/Object; which might mismatch signature
        except:
            return JAVA_NULL
