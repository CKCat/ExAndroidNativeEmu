from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String
from .asset_manager import AssetManager


class Resources(
    Object,
    metaclass=JavaClassDef,
    jvm_name="android/content/res/Resources",
    jvm_super=Object,
):
    def __init__(self, assets, dm, config):
        Object.__init__(self)
        self.__assets = assets
        self.__dm = dm
        self.__config = config

    @staticmethod
    @java_method_def(
        name="getSystem", signature="()Landroid/content/res/Resources;", native=False
    )
    def getSystem(emu):
        # Return a system resources stub
        return Resources(None, None, None)

    @java_method_def(
        name="getString",
        args_list=["jint"],
        signature="(I)Ljava/lang/String;",
        native=False,
    )
    def getString(self, emu, id):
        # Stub: return a dummy string based on ID, or look up if mapped
        return String(f"String-{id}")

    @java_method_def(
        name="getString",
        args_list=["jint", "[Ljava/lang/Object;"],
        signature="(I[Ljava/lang/Object;)Ljava/lang/String;",
        native=False,
    )
    def getStringFmt(self, emu, id, formatArgs):
        return String(f"String-{id}-Formatted")

    @java_method_def(
        name="getAssets", signature="()Landroid/content/res/AssetManager;", native=False
    )
    def getAssets(self, emu):
        return self.__assets
