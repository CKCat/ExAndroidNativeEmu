from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .wifi import NetworkInfo
from loguru import logger


class ConnectivityManager(
    Object,
    metaclass=JavaClassDef,
    jvm_name="android/net/ConnectivityManager",
    jvm_super=Object,
):
    def __init__(self):
        Object.__init__(self)

    @java_method_def(
        name="getActiveNetworkInfo",
        signature="()Landroid/net/NetworkInfo;",
        native=False,
    )
    def getActiveNetworkInfo(self, emu):
        # Return a connected NetworkInfo (WIFI or MOBILE)
        # For emulation, assume WIFI connected
        ni = NetworkInfo()
        # We need to set state on ni if it has setters, or rely on its defaults.
        # wifi.py NetworkInfo needs enhancement first or we use what is there and patch it.
        # It's better if NetworkInfo takes args in init or has setters we can use from python side.
        return ni
