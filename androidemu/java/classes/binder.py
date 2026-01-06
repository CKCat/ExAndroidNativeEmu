from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object


# Interface
class IBinder(
    Object, metaclass=JavaClassDef, jvm_name="android/os/IBinder", jvm_super=Object
):
    def __init__(self):
        Object.__init__(self)


# Class
class Binder(
    Object, metaclass=JavaClassDef, jvm_name="android/os/Binder", jvm_super=Object
):
    def __init__(self):
        Object.__init__(self)

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        pass

    @java_method_def(name="getCallingPid", signature="()I", native=False)
    def getCallingPid(self, emu):
        return 1000  # Dummy PID

    @java_method_def(name="getCallingUid", signature="()I", native=False)
    def getCallingUid(self, emu):
        return 1000  # Dummy UID


class IInterface(metaclass=JavaClassDef, jvm_name="android/os/IInterface"):
    def __init__(self):
        pass
