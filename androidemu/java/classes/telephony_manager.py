from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .string import String


class TelephonyManager(
    metaclass=JavaClassDef, jvm_name="android/telephony/TelephonyManager"
):
    def __init__(self):
        pass

    @java_method_def(name="getDeviceId", signature="()Ljava/lang/String;", native=False)
    def getDeviceId(self, emu, *args, **kwargs):
        val = emu.config.get("imei", "353627071193539")
        return String(val)

    @java_method_def(
        name="getSubscriberId", signature="()Ljava/lang/String;", native=False
    )
    def getSubscriberId(self, emu, *args, **kwargs):
        val = emu.config.get("imsi", "00000000000000")
        return String(val)
