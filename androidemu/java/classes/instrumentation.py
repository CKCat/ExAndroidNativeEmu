from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def


class Instrumentation(metaclass=JavaClassDef, jvm_name="android/app/Instrumentation"):
    def __init__(self):
        pass

    @java_method_def(name="getClass", signature="()Ljava/lang/Class;", native=False)
    def getClass(self, emu):
        return emu.java_classloader.get_class_object(type(self))
