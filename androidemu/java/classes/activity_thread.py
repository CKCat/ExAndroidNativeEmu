from ..classes.context import ContextImpl
from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def
from .application import Application
from .activity import Activity
from .array_map import ArrayMap
from .instrumentation import Instrumentation
from .package_manager import IPackageManager


class ActivityClientRecord(
    metaclass=JavaClassDef,
    jvm_name="android/app/ActivityThread$ActivityClientRecord",
    jvm_fields=[
        JavaFieldDef("paused", "Z", False),
        JavaFieldDef("activity", "Landroid/app/Activity;", False),
    ],
):
    def __init__(self):
        self.paused = False
        self.activity = Activity()


class ActivityThread(
    metaclass=JavaClassDef,
    jvm_name="android/app/ActivityThread",
    jvm_fields=[
        JavaFieldDef("mActivities", "Landroid/util/ArrayMap;", False),
        # Note: Static fields are shared across emulator instances. Fine for stateless objects.
        # 注意：静态字段在所有模拟器实例间共享。对于无状态对象通常没问题。
        JavaFieldDef(
            "sPackageManager",
            "Landroid/content/pm/IPackageManager;",
            True,
            IPackageManager(),
        ),
    ],
):
    s_am = {}

    def __init__(self, pyPkgName):
        self.__ctx_impl = ContextImpl(pyPkgName)
        self.app = Application()
        self.app.attachBaseContext(self.__ctx_impl)
        self.mActivities = ArrayMap([ActivityClientRecord()])
        self.mInstrumentation = Instrumentation()
        # self.mActivities = ArrayMap([])

    @staticmethod
    @java_method_def(
        name="currentActivityThread",
        signature="()Landroid/app/ActivityThread;",
        native=False,
    )
    def currentActivityThread(emu):
        pyPkgName = emu.config.get("pkg_name")
        if pyPkgName not in ActivityThread.s_am:
            ActivityThread.s_am[pyPkgName] = ActivityThread(pyPkgName)
        #
        return ActivityThread.s_am[pyPkgName]

    @staticmethod
    @java_method_def(
        name="currentApplication",
        signature="()Landroid/app/Application;",
        native=False,
    )
    def currentApplication(emu):
        am = ActivityThread.currentActivityThread(emu)
        return am.app

    @java_method_def(
        name="getSystemContext",
        signature="()Landroid/app/ContextImpl;",
        native=False,
    )
    def getSystemContext(self, emu):
        return self.__ctx_impl
