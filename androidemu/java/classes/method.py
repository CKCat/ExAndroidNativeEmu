from loguru import logger

from ...const.java_const import JAVA_NULL
from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import JavaMethodDef, java_method_def
from .executable import Executable


class Method(
    metaclass=JavaClassDef,
    jvm_name="java/lang/reflect/Method",
    jvm_fields=[
        JavaFieldDef("slot", "I", False, ignore=True),
        JavaFieldDef("declaringClass", "Ljava/lang/Class;", False),
    ],
    jvm_super=Executable,
):
    def __init__(self, pydeclaringClass: JavaClassDef, pymethod: JavaMethodDef):
        super().__init__()
        self._method = pymethod
        self.slot = pymethod.jvm_id
        self.declaringClass = pydeclaringClass
        self.accessFlags = pymethod.modifier

    def get_method_id(self):
        return self._method.jvm_id

    @staticmethod
    @java_method_def(
        name="getMethodModifiers",
        signature="(Ljava/lang/Class;I)I",
        args_list=["jobject", "jint"],
    )
    def getMethodModifiers(emu, clazz_obj, jvm_method_id):
        clazz = clazz_obj.value
        method = clazz.find_method_by_id(jvm_method_id)

        logger.debug(
            "Method.getMethodModifiers(%s, %s)" % (clazz.jvm_name, method.name)
        )

        if method.modifier is None:
            raise RuntimeError(
                "No modifier was given to class %s method %s"
                % (clazz.jvm_name, method.name)
            )

        return method.modifier

    @java_method_def(
        name="invoke",
        signature="(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
        args_list=["jobject", "jobject"],
    )
    def invoke(self, emu, obj, args):
        logger.debug("Method.invoke(%r, %r)" % (obj, args))

        py_args = []
        if args and args != JAVA_NULL:
            if hasattr(args, "get_py_items"):
                py_args = args.get_py_items()
            else:
                logger.warning(f"Method.invoke args is not array: {args}")

        if obj == JAVA_NULL:
            # static method
            v = self._method.func(emu, *py_args)

        else:
            v = self._method.func(obj, emu, *py_args)

        return v

    @java_method_def(name="getName", signature="()Ljava/lang/String;", native=False)
    def getName(self, emu):
        from .string import String

        return String(self._method.name)

    @java_method_def(name="getModifiers", signature="()I", native=False)
    def getModifiers(self, emu):
        return self._method.modifier

    @java_method_def(
        name="getDeclaringClass", signature="()Ljava/lang/Class;", native=False
    )
    def getDeclaringClass(self, emu):
        return self.declaringClass.class_object

    def __repr__(self):
        return "Method(%s, %s)" % (self.declaringClass, self._method)
