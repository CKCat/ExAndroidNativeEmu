from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from ..java_field_def import JavaFieldDef
from .object import Object


class DisplayMetrics(
    Object,
    metaclass=JavaClassDef,
    jvm_name="android/util/DisplayMetrics",
    jvm_super=Object,
):
    def __init__(self):
        Object.__init__(self)
        self.widthPixels = 1080
        self.heightPixels = 1920
        self.density = 2.0
        self.densityDpi = 320
        self.scaledDensity = 2.0
        self.xdpi = 320.0
        self.ydpi = 320.0

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        pass

    # Public fields matching Android
    widthPixels = JavaFieldDef("widthPixels", "I", False)
    heightPixels = JavaFieldDef("heightPixels", "I", False)
    density = JavaFieldDef("density", "F", False)
    densityDpi = JavaFieldDef("densityDpi", "I", False)
    scaledDensity = JavaFieldDef("scaledDensity", "F", False)
    xdpi = JavaFieldDef("xdpi", "F", False)
    ydpi = JavaFieldDef("ydpi", "F", False)
