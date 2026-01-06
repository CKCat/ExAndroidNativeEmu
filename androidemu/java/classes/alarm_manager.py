from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object


class AlarmManager(
    Object,
    metaclass=JavaClassDef,
    jvm_name="android/app/AlarmManager",
    jvm_super=Object,
):
    def __init__(self):
        Object.__init__(self)
