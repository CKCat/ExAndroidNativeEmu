from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object


class Bitmap(
    Object, metaclass=JavaClassDef, jvm_name="android/graphics/Bitmap", jvm_super=Object
):
    def __init__(self, width, height, config=None):
        Object.__init__(self)
        self.__width = width
        self.__height = height
        self.__config = config
        self.__recycled = False

    @java_method_def(name="getWidth", signature="()I", native=False)
    def getWidth(self, emu):
        if self.__recycled:
            raise RuntimeError("Bitmap is recycled")
        return self.__width

    @java_method_def(name="getHeight", signature="()I", native=False)
    def getHeight(self, emu):
        if self.__recycled:
            raise RuntimeError("Bitmap is recycled")
        return self.__height

    @java_method_def(name="recycle", signature="()V", native=False)
    def recycle(self, emu):
        self.__recycled = True

    @java_method_def(name="isRecycled", signature="()Z", native=False)
    def isRecycled(self, emu):
        return self.__recycled

    @java_method_def(
        name="compress",
        args_list=[
            "android/graphics/Bitmap$CompressFormat",
            "jint",
            "java/io/OutputStream",
        ],
        signature="(Landroid/graphics/Bitmap$CompressFormat;ILjava/io/OutputStream;)Z",
        native=False,
    )
    def compress(self, emu, format, quality, stream):
        if self.__recycled:
            return False
        # Write dummy data
        # "BM" signature + width + height
        # This is not real image data but allows checking that stream was written to
        from .array import ByteArray

        msg = f"Bitmap({self.__width}x{self.__height})".encode("utf-8")
        barr = ByteArray(bytearray(msg))
        stream.write_bytes(emu, barr)
        return True

    @staticmethod
    @java_method_def(
        name="createBitmap",
        args_list=["jint", "jint", "android/graphics/Bitmap$Config"],
        signature="(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;",
        native=False,
    )
    def createBitmap(emu, width, height, config):
        return Bitmap(width, height, config)


class Config(
    Object,
    metaclass=JavaClassDef,
    jvm_name="android/graphics/Bitmap$Config",
    jvm_super=Object,
):
    def __init__(self):
        Object.__init__(self)


class CompressFormat(
    Object,
    metaclass=JavaClassDef,
    jvm_name="android/graphics/Bitmap$CompressFormat",
    jvm_super=Object,
):
    def __init__(self, name, ordinal):
        Object.__init__(self)
        self.name = name
        self.ordinal = ordinal

    # Static instances would typically be fields here or created
    # We can rely on fields def if we want to expose JPEG, PNG
    # For now just having the class definition allows method signatures to resolve
