from loguru import logger
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .clazz import Class


class Proxy(
    Object, metaclass=JavaClassDef, jvm_name="java/lang/reflect/Proxy", jvm_super=Object
):
    def __init__(self):
        Object.__init__(self)

    @staticmethod
    @java_method_def(
        name="newProxyInstance",
        args_list=["jobject", "jobject", "jobject"],
        signature="(Ljava/lang/ClassLoader;[Ljava/lang/Class;Ljava/lang/reflect/InvocationHandler;)Ljava/lang/Object;",
        native=False,
    )
    def newProxyInstance(emu, loader, interfaces, handler):
        # 1. We need to create a new class (dynamically?) that implements the given interfaces.
        #    For emulation, we might just return an object that traps calls and forwards them to the handler.
        # But 'interfaces' is a Java implementation detail.
        # Here we just return a DynamicProxy object that holds the handler.
        logger.debug(f"Proxy.newProxyInstance called with handler {handler}")

        # In a real generic implementation, we would need to generate a class on the fly.
        # Here we define a localized class (if possible) or just return a generic wrapper.
        return DynamicProxy(handler)


class DynamicProxy(Object):
    def __init__(self, handler):
        Object.__init__(self)
        self.handler = handler
        # jvm_id etc needed? It inherits Object, so it should be fine.
        # BUT, to properly dispatch methods via JNI or Reflection, this object needs to claim it implements the interfaces.
        # For simple emulation usage, maybe not fully needed, but let's see.

    # If the user calls methods on this proxy, we need to intercept them?
    # Regular Python calls won't match Java method lookup unless we register them.
    # This is complex. For now, returning a dummy object that holds the handler is the first step.
    pass
