from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object


class AudioManager(
    Object,
    metaclass=JavaClassDef,
    jvm_name="android/media/AudioManager",
    jvm_super=Object,
):
    def __init__(self):
        Object.__init__(self)

    # Common constant
    STREAM_MUSIC = 3
