from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object


class Looper(
    Object, metaclass=JavaClassDef, jvm_name="android/os/Looper", jvm_super=Object
):
    sMainLooper = None

    def __init__(self, main=False):
        Object.__init__(self)
        self.__is_main = main
        self.__queue = None  # MessageQueue stub

    @staticmethod
    @java_method_def(
        name="getMainLooper", signature="()Landroid/os/Looper;", native=False
    )
    def getMainLooper(emu):
        if Looper.sMainLooper is None:
            Looper.sMainLooper = Looper(main=True)
        return Looper.sMainLooper

    @staticmethod
    @java_method_def(name="myLooper", signature="()Landroid/os/Looper;", native=False)
    def myLooper(emu):
        # For emulation, assume we are on main thread usually.
        return Looper.getMainLooper(emu)

    @staticmethod
    @java_method_def(name="loop", signature="()V", native=False)
    def loop(emu):
        # Stub: infinite loop processing messages
        pass

    @staticmethod
    @java_method_def(name="prepare", signature="()V", native=False)
    def prepare(emu):
        # Stub
        pass
