from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from .field import AccessibleObject


class Executable(
    AccessibleObject,
    metaclass=JavaClassDef,
    jvm_name="java/lang/reflect/Executable",
    jvm_fields=[JavaFieldDef("accessFlags", "I", False)],
    jvm_super=AccessibleObject,
):
    def __init__(self):
        AccessibleObject.__init__(self)
