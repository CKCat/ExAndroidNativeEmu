from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def
from .string import String
from .object import Object


class BuildVersion(
    Object,
    metaclass=JavaClassDef,
    jvm_name="android/os/Build$VERSION",
    jvm_super=Object,
):
    def __init__(self):
        Object.__init__(self)

    # Static fields will be populated by the class loader or init logic if we define them here.
    # However, since these are static finals usually, we can define them as Python attributes or via JavaFieldDef.
    # But Build.VERSION fields are static.
    # In this emulator, we often define static fields on the Class definition.

    SDK_INT = JavaFieldDef("SDK_INT", "I", True, 23)  # Default API 23 (Marshmallow)
    RELEASE = JavaFieldDef("RELEASE", "Ljava/lang/String;", True, String("6.0.1"))
    INCREMENTAL = JavaFieldDef(
        "INCREMENTAL", "Ljava/lang/String;", True, String("user.20160101")
    )


class Build(
    Object, metaclass=JavaClassDef, jvm_name="android/os/Build", jvm_super=Object
):
    def __init__(self):
        Object.__init__(self)

    # Static Fields
    UNKNOWN = String("unknown")

    BOARD = JavaFieldDef("BOARD", "Ljava/lang/String;", True, String("msm8996"))
    BOOTLOADER = JavaFieldDef(
        "BOOTLOADER", "Ljava/lang/String;", True, String("unknown")
    )
    BRAND = JavaFieldDef("BRAND", "Ljava/lang/String;", True, String("Samsung"))
    CPU_ABI = JavaFieldDef("CPU_ABI", "Ljava/lang/String;", True, String("arm64-v8a"))
    CPU_ABI2 = JavaFieldDef("CPU_ABI2", "Ljava/lang/String;", True, String(""))
    DEVICE = JavaFieldDef("DEVICE", "Ljava/lang/String;", True, String("herolte"))
    DISPLAY = JavaFieldDef("DISPLAY", "Ljava/lang/String;", True, String("MMB29K"))
    FINGERPRINT = JavaFieldDef(
        "FINGERPRINT",
        "Ljava/lang/String;",
        True,
        String(
            "samsung/heroltexx/herolte:6.0.1/MMB29K/G930FXXU1APGO:user/release-keys"
        ),
    )
    HARDWARE = JavaFieldDef(
        "HARDWARE", "Ljava/lang/String;", True, String("samsungexynos8890")
    )
    HOST = JavaFieldDef("HOST", "Ljava/lang/String;", True, String("SWDD6316"))
    ID = JavaFieldDef("ID", "Ljava/lang/String;", True, String("MMB29K"))
    MANUFACTURER = JavaFieldDef(
        "MANUFACTURER", "Ljava/lang/String;", True, String("samsung")
    )
    MODEL = JavaFieldDef("MODEL", "Ljava/lang/String;", True, String("SM-G930F"))
    PRODUCT = JavaFieldDef("PRODUCT", "Ljava/lang/String;", True, String("heroltexx"))
    RADIO = JavaFieldDef("RADIO", "Ljava/lang/String;", True, String("unknown"))
    TAGS = JavaFieldDef("TAGS", "Ljava/lang/String;", True, String("release-keys"))
    TYPE = JavaFieldDef("TYPE", "Ljava/lang/String;", True, String("user"))
    USER = JavaFieldDef("USER", "Ljava/lang/String;", True, String("dpi"))
