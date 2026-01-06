from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from ..java_field_def import JavaFieldDef
from .object import Object
from .bitmap import Bitmap


class BitmapFactory(
    Object,
    metaclass=JavaClassDef,
    jvm_name="android/graphics/BitmapFactory",
    jvm_super=Object,
):
    def __init__(self):
        Object.__init__(self)

    @staticmethod
    @java_method_def(
        name="decodeByteArray",
        args_list=["[B", "jint", "jint"],
        signature="([BII)Landroid/graphics/Bitmap;",
        native=False,
    )
    def decodeByteArray(emu, data, offset, length):
        # Stub: Return a 100x100 bitmap
        return Bitmap(100, 100)

    @staticmethod
    @java_method_def(
        name="decodeFile",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Landroid/graphics/Bitmap;",
        native=False,
    )
    def decodeFile(emu, path_obj):
        # Stub
        return Bitmap(100, 100)

    @staticmethod
    @java_method_def(
        name="decodeResource",
        args_list=["Landroid/content/res/Resources;", "jint"],
        signature="(Landroid/content/res/Resources;I)Landroid/graphics/Bitmap;",
        native=False,
    )
    def decodeResource(emu, res, id):
        # Stub
        return Bitmap(100, 100)


class Options(
    Object,
    metaclass=JavaClassDef,
    jvm_name="android/graphics/BitmapFactory$Options",
    jvm_super=Object,
):
    def __init__(self):
        Object.__init__(self)
        self.inPreferredConfig = None
        self.inJustDecodeBounds = False
        self.inSampleSize = 1
        self.outWidth = 0
        self.outHeight = 0
        self.outMimeType = None

    # Define fields
    inPreferredConfig_field = JavaFieldDef(
        "inPreferredConfig", "Landroid/graphics/Bitmap$Config;", False
    )
    inJustDecodeBounds_field = JavaFieldDef("inJustDecodeBounds", "Z", False)
    inSampleSize_field = JavaFieldDef("inSampleSize", "I", False)
    outWidth_field = JavaFieldDef("outWidth", "I", False)
    outHeight_field = JavaFieldDef("outHeight", "I", False)
    outMimeType_field = JavaFieldDef("outMimeType", "Ljava/lang/String;", False)
