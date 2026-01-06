from loguru import logger

from ...const.java_const import JAVA_NULL
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def


class AccessibleObject(
    metaclass=JavaClassDef, jvm_name="java/lang/reflect/AccessibleObject"
):
    def __init__(self):
        pass

    @java_method_def(
        name="setAccessible",
        args_list=["jboolean"],
        signature="(Z)V",
        native=False,
    )
    def setAccessible(self, emu, access):
        logger.debug("AccessibleObject setAccessible call skip")


class Field(
    AccessibleObject,
    metaclass=JavaClassDef,
    jvm_name="java/lang/reflect/Field",
    jvm_super=AccessibleObject,
):
    def __init__(self, pydeclaringClass: JavaClassDef, fieldName: str):
        super().__init__()
        self.__fieldName = fieldName
        self.declaringClass = pydeclaringClass
        self.__field_def = None

        # Find Field Def
        if pydeclaringClass:
            for f in pydeclaringClass.jvm_fields.values():
                if f.name == fieldName:
                    self.__field_def = f
                    break

    @java_method_def(name="getName", signature="()Ljava/lang/String;", native=False)
    def getName(self, emu):
        from .string import String

        return String(self.__fieldName)

    @java_method_def(name="getType", signature="()Ljava/lang/Class;", native=False)
    def getType(self, emu):
        if not self.__field_def:
            return JAVA_NULL  # Should not happen if field exists

        sig = self.__field_def.signature
        # Handle primitives?
        # For now, let's try to load class by name if it's an object type.
        if sig.startswith("L") and sig.endswith(";"):
            # Ljava/lang/String; -> java.lang.String
            cls_name = sig[1:-1].replace("/", ".")
            from .clazz import Class
            from .string import String

            try:
                return Class.forName(emu, String(cls_name))
            except Exception as e:
                logger.error(f"Field.getType class not found: {cls_name}, error: {e}")
                pass

        # Fallback for primitives or failures
        return JAVA_NULL

    @java_method_def(name="getModifiers", signature="()I", native=False)
    def getModifiers(self, emu):
        if self.__field_def:
            return self.__field_def.access_flags
        return 0

    @java_method_def(
        name="get",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)Ljava/lang/Object;",
        native=False,
    )
    def get(self, emu, obj):
        logger.debug("Field.get(%r)" % obj)
        v = getattr(obj, self.__fieldName)
        return v

    @java_method_def(
        name="getInt",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)I",
        native=False,
    )
    def getInt(self, emu, obj):
        logger.debug("Field.getInt(%r)" % obj)
        v = getattr(obj, self.__fieldName)
        return int(v)

    @java_method_def(
        name="setInt",
        args_list=["jobject", "jint"],
        signature="(Ljava/lang/Object;I)V",
        native=False,
    )
    def setInt(self, emu, obj, val):
        logger.debug("Field.setInt(%r, %r)" % (obj, val))
        setattr(obj, self.__fieldName, val)

    @java_method_def(
        name="set",
        args_list=["jobject", "jobject"],
        signature="(Ljava/lang/Object;Ljava/lang/Object;)V",
        native=False,
    )
    def set(self, emu, obj, val):
        logger.debug("Field.set(%r, %r)" % (obj, val))
        setattr(obj, self.__fieldName, val)
