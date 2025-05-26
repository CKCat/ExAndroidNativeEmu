from ..java_class_def import JavaClassDef
from .context import ContextWrapper


class Application(
    ContextWrapper,
    metaclass=JavaClassDef,
    jvm_name="android/app/Application",
    jvm_super=ContextWrapper,
):
    def __init__(self):
        pass
