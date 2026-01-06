from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object


class ActivityManager(
    Object,
    metaclass=JavaClassDef,
    jvm_name="android/app/ActivityManager",
    jvm_super=Object,
):
    def __init__(self):
        Object.__init__(self)

    @staticmethod
    @java_method_def(name="isUserAMonkey", signature="()Z", native=False)
    def isUserAMonkey(emu):
        return False


class IActivityManager(metaclass=JavaClassDef, jvm_name="android/app/IActivityManager"):
    def __init__(self):
        pass

    @java_method_def(name="getClass", signature="()Ljava/lang/Class;", native=False)
    def getClass(self, emu):
        return emu.java_classloader.get_class_object(type(self))


class ActivityManagerNative(
    metaclass=JavaClassDef, jvm_name="android/app/ActivityManagerNative"
):
    def __init__(self):
        pass

    @staticmethod
    @java_method_def(
        name="getDefault",
        signature="()android/app/IActivityManager;",
        native=False,
    )
    def getDefault(emu):
        return IActivityManager()
