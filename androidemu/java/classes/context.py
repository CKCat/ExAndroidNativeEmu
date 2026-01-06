from loguru import logger
from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def
from .asset_manager import AssetManager
from .contentresolver import ContentResolver
from .file import File
from .package_manager import PackageManager
from .share_preference import SharedPreferences
from .string import String
from .wifi import WifiManager
from .telephony_manager import TelephonyManager
from .activity_manager import ActivityManager
from .audio_manager import AudioManager
from .alarm_manager import AlarmManager
from .connectivity_manager import ConnectivityManager
from .class_loader import BaseClassLoader


class Context(
    metaclass=JavaClassDef,
    jvm_name="android/content/Context",
    jvm_fields=[
        JavaFieldDef("WIFI_SERVICE", "Ljava/lang/String;", True, String("wifi")),
        JavaFieldDef("TELEPHONY_SERVICE", "Ljava/lang/String;", True, String("phone")),
        JavaFieldDef(
            "CONNECTIVITY_SERVICE",
            "Ljava/lang/String;",
            True,
            String("connectivity"),
        ),
        JavaFieldDef(
            "ACTIVITY_SERVICE", "Ljava/lang/String;", True, String("activity")
        ),
        JavaFieldDef("AUDIO_SERVICE", "Ljava/lang/String;", True, String("audio")),
        JavaFieldDef("ALARM_SERVICE", "Ljava/lang/String;", True, String("alarm")),
        JavaFieldDef(
            "CONNECTIVITY_SERVICE",
            "Ljava/lang/String;",
            True,
            String("connectivity"),
        ),
    ],
):
    def __init__(self):
        pass

    @java_method_def(
        name="getPackageManager",
        signature="()Landroid/content/pm/PackageManager;",
        native=False,
    )
    def getPackageManager(self, emu):
        raise RuntimeError("pure virtual function call!!!")

    @java_method_def(
        name="getContentResolver",
        signature="()Landroid/content/ContentResolver;",
        native=False,
    )
    def getContentResolver(self, emu):
        raise RuntimeError("pure virtual function call!!!")

    @java_method_def(
        name="getSystemService",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/Object;",
        native=False,
    )
    def getSystemService(self, emu, s1):
        raise RuntimeError("pure virtual function call!!!")

    @java_method_def(
        name="getApplicationInfo",
        signature="()Landroid/content/pm/ApplicationInfo;",
        native=False,
    )
    def getApplicationInfo(self, emu):
        raise RuntimeError("pure virtual function call!!!")

    @java_method_def(
        name="checkSelfPermission",
        signature="(Ljava/lang/String;)I",
        native=False,
    )
    def checkSelfPermission(self, emu):
        raise RuntimeError("pure virtual function call!!!")

    @java_method_def(
        name="checkCallingOrSelfPermission",
        signature="(Ljava/lang/String;)I",
        native=False,
    )
    def checkCallingOrSelfPermission(self, emu):
        raise RuntimeError("pure virtual function call!!!")

    @java_method_def(
        name="getPackageCodePath",
        signature="()Ljava/lang/String;",
        native=False,
    )
    def getPackageCodePath(self, emu):
        raise RuntimeError("pure virtual function call!!!")

    @java_method_def(name="getFilesDir", signature="()Ljava/io/File;", native=False)
    def getFilesDir(self, emu):
        raise RuntimeError("pure virtual function call!!!")

    @java_method_def(
        name="getPackageName", signature="()Ljava/lang/String;", native=False
    )
    def getPackageName(self, emu):
        raise RuntimeError("pure virtual function call!!!")

    @java_method_def(
        name="getSharedPreferences",
        args_list=["jstring", "jint"],
        signature="(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
        native=False,
    )
    def getSharedPreferences(self, emu, name, mode):
        raise RuntimeError("pure virtual function call!!!")

    @java_method_def(
        name="getResources",
        signature="()Landroid/content/res/Resources;",
        native=False,
    )
    def getResources(self, emu):
        raise RuntimeError("pure virtual function call!!!")

    @java_method_def(
        name="getString",
        args_list=["jint"],
        signature="(I)Ljava/lang/String;",
        native=False,
    )
    def getString(self, emu, resId):
        raise RuntimeError("pure virtual function call!!!")


class ContextImpl(
    Context,
    metaclass=JavaClassDef,
    jvm_name="android/app/ContextImpl",
    jvm_super=Context,
):
    def __init__(self, pyPkgName):
        Context.__init__(self)

        self.__pkgName = String(pyPkgName)
        self.__pkg_mgr = PackageManager(pyPkgName)
        self.__resolver = ContentResolver()
        self.__asset_mgr = None
        self.__resources = None
        self.__service_map = {
            "phone": TelephonyManager,
            "wifi": WifiManager,
            "connectivity": ConnectivityManager,
            "activity": ActivityManager,
            "audio": AudioManager,
            "alarm": AlarmManager,
        }
        self.__class_loader = BaseClassLoader()

    @java_method_def(
        name="getPackageManager",
        signature="()Landroid/content/pm/PackageManager;",
        native=False,
    )
    def getPackageManager(self, emu):
        return self.__pkg_mgr

    @java_method_def(
        name="getAssets",
        signature="()Landroid/content/res/AssetManager;",
        native=False,
    )
    def getAssets(self, emu):
        if not self.__asset_mgr:
            # 调用getAssets才初始化assert_manager
            # 因为不是每个so模拟执行都需要打开apk
            pyapk_path = self.__pkg_mgr.getPackageInfo(
                emu, self.__pkgName, 0
            ).applicationInfo.sourceDir.get_py_string()
            self.__asset_mgr = AssetManager(emu, pyapk_path)

        return self.__asset_mgr

    @java_method_def(
        name="getContentResolver",
        signature="()Landroid/content/ContentResolver;",
        native=False,
    )
    def getContentResolver(self, emu):
        return self.__resolver

    @java_method_def(
        name="getSystemService",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/Object;",
        native=False,
    )
    def getSystemService(self, emu, s1):
        stype = s1.get_py_string()
        if stype in self.__service_map:
            return self.__service_map[stype]()

        logger.warning(f"getSystemService {stype} not implemented")
        return None

    @java_method_def(
        name="getApplicationInfo",
        signature="()Landroid/content/pm/ApplicationInfo;",
        native=False,
    )
    def getApplicationInfo(self, emu):
        pkgMgr = self.__pkg_mgr
        pkgInfo = pkgMgr.getPackageInfo(emu, self.__pkgName, 0)
        return pkgInfo.applicationInfo

    @java_method_def(
        name="getPackageName", signature="()Ljava/lang/String;", native=False
    )
    def getPackageName(self, emu):
        return self.__pkgName

    @java_method_def(
        name="checkSelfPermission",
        signature="(Ljava/lang/String;)I",
        native=False,
    )
    def checkSelfPermission(self, emu):
        return 0  # PERMISSION_GRANTED

    @java_method_def(
        name="checkCallingOrSelfPermission",
        signature="(Ljava/lang/String;)I",
        native=False,
    )
    def checkCallingOrSelfPermission(self, emu):
        return 0  # PERMISSION_GRANTED

    @java_method_def(
        name="getPackageCodePath",
        signature="()Ljava/lang/String;",
        native=False,
    )
    def getPackageCodePath(self, emu):
        pkgName = emu.config.get("pkg_name")
        path = "/data/app/%s-1.apk" % (pkgName,)
        return String(path)

    @java_method_def(name="getFilesDir", signature="()Ljava/io/File;", native=False)
    def getFilesDir(self, emu):
        pkgName = emu.config.get("pkg_name")
        fdir = "/data/data/%s/files" % (pkgName,)
        return File(fdir)

    @java_method_def(
        name="getSharedPreferences",
        args_list=["jstring", "jint"],
        signature="(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
        native=False,
    )
    def getSharedPreferences(self, emu, name, mode):
        pkgName = emu.config.get("pkg_name")
        pyName = name.get_py_string()
        if pyName in self.__sp_map:
            return self.__sp_map[pyName]

        else:
            path = "/data/data/%s/shared_prefs/%s.xml" % (pkgName, pyName)
            sp = SharedPreferences(emu, path)
            self.__sp_map[pyName] = sp
            return sp

    @java_method_def(
        name="getResources",
        signature="()Landroid/content/res/Resources;",
        native=False,
    )
    def getResources(self, emu):
        if not self.__resources:
            assets = self.getAssets(emu)
            from .resources import Resources

            self.__resources = Resources(assets, None, None)
        return self.__resources

    @java_method_def(
        name="getString",
        args_list=["jint"],
        signature="(I)Ljava/lang/String;",
        native=False,
    )
    def getString(self, emu, resId):
        return self.getResources(emu).getString(emu, resId)

    @java_method_def(
        name="getClassLoader",
        signature="()Ljava/lang/ClassLoader;",
        native=False,
    )
    def getClassLoader(self, emu):
        return self.__class_loader

    @java_method_def(
        name="registerReceiver",
        args_list=[
            "Landroid/content/BroadcastReceiver;",
            "Landroid/content/IntentFilter;",
        ],
        signature="(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;",
        native=False,
    )
    def registerReceiver(self, emu, receiver, filter):
        logger.warning("registerReceiver not implemented")
        return None

    @java_method_def(
        name="sendBroadcast",
        args_list=["Landroid/content/Intent;"],
        signature="(Landroid/content/Intent;)V",
        native=False,
    )
    def sendBroadcast(self, emu, intent):
        logger.warning("sendBroadcast not implemented")


class ContextWrapper(
    Context,
    metaclass=JavaClassDef,
    jvm_name="android/content/ContextWrapper",
    jvm_super=Context,
):
    def __init__(self):
        Context.__init__(self)
        self.__impl = None

    def attachBaseContext(self, ctx_impl):
        self.__impl = ctx_impl

    @java_method_def(
        name="getPackageManager",
        signature="()Landroid/content/pm/PackageManager;",
        native=False,
    )
    def getPackageManager(self, emu):
        return self.__impl.getPackageManager(emu)

    @java_method_def(
        name="getAssets",
        signature="()Landroid/content/res/AssetManager;",
        native=False,
    )
    def getAssets(self, emu):
        return self.__impl.getAssets(emu)

    @java_method_def(
        name="getContentResolver",
        signature="()Landroid/content/ContentResolver;",
        native=False,
    )
    def getContentResolver(self, emu):
        return self.__impl.getContentResolver(emu)

    @java_method_def(
        name="getSystemService",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/Object;",
        native=False,
    )
    def getSystemService(self, emu, s1):
        return self.__impl.getSystemService(emu, s1)

    @java_method_def(
        name="getApplicationInfo",
        signature="()Landroid/content/pm/ApplicationInfo;",
        native=False,
    )
    def getApplicationInfo(self, emu):
        return self.__impl.getApplicationInfo(emu)

    @java_method_def(
        name="getPackageName", signature="()Ljava/lang/String;", native=False
    )
    def getPackageName(self, emu):
        return self.__impl.getPackageName(emu)

    @java_method_def(
        name="checkSelfPermission",
        signature="(Ljava/lang/String;)I",
        native=False,
    )
    def checkSelfPermission(self, emu):
        return self.__impl.checkSelfPermission(emu)

    @java_method_def(
        name="checkCallingOrSelfPermission",
        signature="(Ljava/lang/String;)I",
        native=False,
    )
    def checkCallingOrSelfPermission(self, emu):
        return self.__impl.checkCallingOrSelfPermission(emu)

    @java_method_def(
        name="getPackageCodePath",
        signature="()Ljava/lang/String;",
        native=False,
    )
    def getPackageCodePath(self, emu):
        return self.__impl.getPackageCodePath(emu)

    @java_method_def(name="getFilesDir", signature="()Ljava/io/File;", native=False)
    def getFilesDir(self, emu):
        return self.__impl.getFilesDir(emu)

    @java_method_def(
        name="getSharedPreferences",
        args_list=["jstring", "jint"],
        signature="(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
        native=False,
    )
    def getSharedPreferences(self, emu, name, mode):
        return self.__impl.getSharedPreferences(emu, name, mode)

    @java_method_def(
        name="getResources",
        signature="()Landroid/content/res/Resources;",
        native=False,
    )
    def getResources(self, emu):
        return self.__impl.getResources(emu)

    @java_method_def(
        name="getString",
        args_list=["jint"],
        signature="(I)Ljava/lang/String;",
        native=False,
    )
    def getString(self, emu, resId):
        return self.__impl.getString(emu, resId)

    @java_method_def(
        name="getClassLoader",
        signature="()Ljava/lang/ClassLoader;",
        native=False,
    )
    def getClassLoader(self, emu):
        return self.__impl.getClassLoader(emu)

    @java_method_def(
        name="registerReceiver",
        args_list=[
            "Landroid/content/BroadcastReceiver;",
            "Landroid/content/IntentFilter;",
        ],
        signature="(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;",
        native=False,
    )
    def registerReceiver(self, emu, receiver, filter):
        return self.__impl.registerReceiver(emu, receiver, filter)

    @java_method_def(
        name="sendBroadcast",
        args_list=["Landroid/content/Intent;"],
        signature="(Landroid/content/Intent;)V",
        native=False,
    )
    def sendBroadcast(self, emu, intent):
        self.__impl.sendBroadcast(emu, intent)
