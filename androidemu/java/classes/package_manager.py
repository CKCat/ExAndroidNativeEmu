import time

from loguru import logger

from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def
from .array import ByteArray, ObjectArray
from .string import String


class Signature(metaclass=JavaClassDef, jvm_name="android/content/pm/Signature"):
    def __init__(self, sign_hex):
        self.__sign_hex = sign_hex

    @java_method_def(name="toByteArray", signature="()[B", native=False)
    def toByteArray(self, emu):
        if self.__sign_hex is None:
            return ByteArray(bytearray())
        bs = bytes.fromhex(self.__sign_hex)
        return ByteArray(bytearray(bs))

    @java_method_def(
        name="toCharsString", signature="()Ljava/lang/String;", native=False
    )
    def toCharsString(self, emu):
        return String(self.__sign_hex)


class ApplicationInfo(
    metaclass=JavaClassDef,
    jvm_name="android/content/pm/ApplicationInfo",
    jvm_fields=[
        JavaFieldDef("sourceDir", "Ljava/lang/String;", False),
        JavaFieldDef("dataDir", "Ljava/lang/String;", False),
        JavaFieldDef("nativeLibraryDir", "Ljava/lang/String;", False),
        JavaFieldDef("flags", "I", False),
    ],
):
    def __init__(self, pyPkgName):
        self.sourceDir = String("/data/app/%s-1.apk" % pyPkgName)
        self.dataDir = String("/data/data/%s" % pyPkgName)
        self.nativeLibraryDir = String("/data/data/%s" % pyPkgName)
        self.flags = 0x30E8BF46


class PackageInfo(
    metaclass=JavaClassDef,
    jvm_name="android/content/pm/PackageInfo",
    jvm_fields=[
        JavaFieldDef("applicationInfo", "Landroid/content/pm/ApplicationInfo;", False),
        JavaFieldDef("firstInstallTime", "J", False),
        JavaFieldDef("lastUpdateTime", "J", False),
        JavaFieldDef("signatures", "[Landroid/content/pm/Signature;", False),
        JavaFieldDef("versionCode", "I", False),
    ],
):
    s_t = time.time()

    def __init__(self, pyPkgName, sign_hex, version_code):
        self.applicationInfo = ApplicationInfo(pyPkgName)
        self.firstInstallTime = int(PackageInfo.s_t)
        self.lastUpdateTime = self.firstInstallTime
        self.versionCode = version_code
        if sign_hex:
            self.signatures = ObjectArray([Signature(sign_hex)])


class PackageItemInfo(
    metaclass=JavaClassDef,
    jvm_name="android/content/pm/PackageItemInfo",
    jvm_fields=[
        JavaFieldDef("name", "Ljava/lang/String;", False),
        JavaFieldDef("packageName", "Ljava/lang/String;", False),
    ],
):
    def __init__(self):
        self.name = String("")
        self.packageName = String("")


class ComponentInfo(
    PackageItemInfo,
    metaclass=JavaClassDef,
    jvm_name="android/content/pm/ComponentInfo",
    jvm_super=PackageItemInfo,
    jvm_fields=[
        JavaFieldDef("applicationInfo", "Landroid/content/pm/ApplicationInfo;", False),
        JavaFieldDef("processName", "Ljava/lang/String;", False),
        JavaFieldDef("enabled", "Z", False),
        JavaFieldDef("exported", "Z", False),
    ],
):
    def __init__(self):
        PackageItemInfo.__init__(self)
        self.applicationInfo = None
        self.processName = String("")
        self.enabled = True
        self.exported = False


class ActivityInfo(
    ComponentInfo,
    metaclass=JavaClassDef,
    jvm_name="android/content/pm/ActivityInfo",
    jvm_super=ComponentInfo,
    jvm_fields=[
        JavaFieldDef("launchMode", "I", False),
        JavaFieldDef("screenOrientation", "I", False),
    ],
):
    def __init__(self):
        ComponentInfo.__init__(self)
        self.launchMode = 0
        self.screenOrientation = -1


class ResolveInfo(
    metaclass=JavaClassDef,
    jvm_name="android/content/pm/ResolveInfo",
    jvm_fields=[
        JavaFieldDef("activityInfo", "Landroid/content/pm/ActivityInfo;", False),
        JavaFieldDef("priority", "I", False),
        JavaFieldDef("preferredOrder", "I", False),
        JavaFieldDef("match", "I", False),
    ],
):
    def __init__(self):
        self.activityInfo = ActivityInfo()
        self.priority = 0
        self.preferredOrder = 0
        self.match = 0


# android中真正PackageManager是抽象类,真正实现类是ApplicationPackageManager,这里简化
class PackageManager(
    metaclass=JavaClassDef,
    jvm_name="android/content/pm/PackageManager",
    jvm_fields=[
        JavaFieldDef("GET_SIGNATURES", "I", True, 64),
    ],
):
    GET_SIGNATURES = 64
    s_packages = {}

    def __init__(self, pyPkgName):
        self.__pyPkgName = pyPkgName
        # Register self if not exists, assuming self is the main package
        # Note: Ideally this should be done by the system installation process,
        # but here we auto-register for convenience.
        if pyPkgName and pyPkgName not in PackageManager.s_packages:
            # We need a way to get version code and signature here if we want to store it accurately
            # But for now we defer that to getPackageInfo call or config
            pass

    @staticmethod
    def add_package(package_name, package_info):
        PackageManager.s_packages[package_name] = package_info

    @java_method_def(
        name="getPackageInfo",
        args_list=["jstring", "jint"],
        signature="(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
        native=False,
    )
    def getPackageInfo(self, emu, package_name, flags):
        py_package_name = package_name.get_py_string()

        # Check explicit registry first
        if py_package_name in PackageManager.s_packages:
            logger.debug(f"getPackageInfo hit registry for {py_package_name}")
            return PackageManager.s_packages[py_package_name]

        if py_package_name != self.__pyPkgName:
            # Return a dummy PackageInfo for other packages to prevent crashes,
            # but log it so user knows they might want to register it.
            logger.warning(
                f"getPackageInfo called for {py_package_name}, returning dummy info. "
                "Use PackageManager.add_package() to register it if needed."
            )
            return PackageInfo(py_package_name, None, 0)

        sign_hex = emu.config.get("sign_hex", "0")
        if flags == PackageManager.GET_SIGNATURES:
            if sign_hex == "0":
                raise RuntimeError(
                    "getPackageInfo with PackageManager.GET_SIGNATURES is called but no 'sign_hex' set in config!!!"
                )

        version_code = emu.config.get("version_code")
        if version_code is None:
            version_code = 0
            logger.debug("version_code not config default to 0")

        pkg_info = PackageInfo(self.__pyPkgName, sign_hex, version_code)
        return pkg_info

    @java_method_def(
        name="getApplicationInfo",
        args_list=["jstring", "jint"],
        signature="(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;",
        native=False,
    )
    def getApplicationInfo(self, emu, package_name, flags):
        # reuse getPackageInfo logic
        pkg_info = self.getPackageInfo(emu, package_name, 0)
        return pkg_info.applicationInfo

    @java_method_def(
        name="resolveActivity",
        args_list=["jobject", "jint"],
        signature="(Landroid/content/Intent;I)Landroid/content/pm/ResolveInfo;",
        native=False,
    )
    def resolveActivity(self, emu, intent, flags):
        logger.debug("resolveActivity called, returning default ResolveInfo")
        res = ResolveInfo()
        # Ensure activityInfo.applicationInfo is set if needed
        res.activityInfo.applicationInfo = self.getApplicationInfo(
            emu, String(self.__pyPkgName), 0
        )
        return res

    @java_method_def(
        name="queryIntentActivities",
        args_list=["jobject", "jint"],
        signature="(Landroid/content/Intent;I)Ljava/util/List;",
        native=False,
    )
    def queryIntentActivities(self, emu, intent, flags):
        from .list import ArrayList

        logger.debug("queryIntentActivities called")
        activity_list = ArrayList([])
        # We could add the default resolve info here if we want to simulate finding an activity.
        # For now, empty list is a valid response (no match).
        return activity_list

    @java_method_def(
        name="checkPermission",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)I",
        native=False,
    )
    def checkPermission(self, *args, **kwargs):
        #     PERMISSION_DENIED = -1;
        #     PERMISSION_GRANTED = 0;
        # logger.debug('Check Permission %s, %s' % (args[1], args[2]))
        return 0


class IPackageManager(
    metaclass=JavaClassDef,
    jvm_name="android/content/pm/IPackageManager",
    jvm_fields=[],
):
    def __init__(self):
        pass
