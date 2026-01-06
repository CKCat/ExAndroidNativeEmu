from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from ...const.java_const import JAVA_NULL


class Object(metaclass=JavaClassDef, jvm_name="java/lang/Object"):
    def __init__(self):
        pass

    @java_method_def(name="getClass", signature="()Ljava/lang/Class;", native=False)
    def getClass(self, emu):
        return self.class_object

    @java_method_def(name="hashCode", signature="()I", native=False)
    def hashCode(self, emu):
        return id(self)

    @java_method_def(
        name="equals",
        signature="(Ljava/lang/Object;)Z",
        args_list=["jobject"],
        native=False,
    )
    def equals(self, emu, other):
        return self is other

    @java_method_def(name="toString", signature="()Ljava/lang/String;", native=False)
    def toString(self, emu):
        from .string import String

        # Default toString: getClass().getName() + '@' + Integer.toHexString(hashCode())
        # Simplified: ClassName + @ + hex(id)
        clazz = self.class_object
        if clazz:
            # Need to call getName on Class object, but here we can just use jvm_name or descriptor
            # If clazz is a Class instance, it has getName method.
            # But invoking java method from python inside implementation might be tricky if not careful.
            # Let's try to access descriptor directly if available or use Class.getName implementation logic
            name_str = clazz.get_jni_descriptor().replace("/", ".")
            # Handle generics or L; cleanup
            if name_str.startswith("L") and name_str.endswith(";"):
                name_str = name_str[1:-1]
            return String(f"{name_str}@{id(self):x}")
        return String(f"Object@{id(self):x}")

    @java_method_def(name="wait", signature="()V", native=False)
    def wait(self, emu):
        pass

    @java_method_def(name="wait", signature="(J)V", args_list=["jlong"], native=False)
    def wait_timeout(self, emu, timeout):
        pass

    @java_method_def(
        name="wait", signature="(JI)V", args_list=["jlong", "jint"], native=False
    )
    def wait_timeout_nanos(self, emu, timeout, nanos):
        pass

    @java_method_def(name="notify", signature="()V", native=False)
    def notify(self, emu):
        pass

    @java_method_def(name="notifyAll", signature="()V", native=False)
    def notifyAll(self, emu):
        pass
