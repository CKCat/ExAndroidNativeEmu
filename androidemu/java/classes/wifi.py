from ..classes.list import List
from ..classes.string import String
from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def
from .object import Object


class WifiInfo(metaclass=JavaClassDef, jvm_name="android/net/wifi/WifiInfo"):
    def __init__(self):
        pass

    @java_method_def(
        name="getMacAddress", signature="()Ljava/lang/String;", native=False
    )
    def getMacAddress(self, emu, *args, **kwargs):
        mac = emu.config.get("mac", [0x02, 0x00, 0x00, 0x00, 0x00, 0x00])
        s = "%02x:%02x:%02x:%02x:%02x:%02x" % (
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5],
        )
        return String(s)

    @java_method_def(name="getBSSID", signature="()Ljava/lang/String;", native=False)
    def getBSSID(self, emu, *args, **kwargs):
        val = emu.config.get("bssid", "00:00:00:00:00:00")
        return String(val)

    @java_method_def(name="getSSID", signature="()Ljava/lang/String;", native=False)
    def getSSID(self, emu, *args, **kwargs):
        val = emu.config.get("ssid", "<unknown ssid>")
        return String(val)


class NetworkInfo(
    Object, metaclass=JavaClassDef, jvm_name="android/net/NetworkInfo", jvm_super=Object
):
    def __init__(self, type_int=1, type_name="WIFI", state="CONNECTED"):
        Object.__init__(self)
        self.__type = type_int
        self.__typeName = type_name
        self.__state = state
        self.__isConnected = True

    @java_method_def(name="getType", signature="()I", native=False)
    def getType(self, emu):
        return self.__type

    @java_method_def(name="getTypeName", signature="()Ljava/lang/String;", native=False)
    def getTypeName(self, emu):
        return String(self.__typeName)

    @java_method_def(name="isConnected", signature="()Z", native=False)
    def isConnected(self, emu):
        return self.__isConnected

    @java_method_def(name="isConnectedOrConnecting", signature="()Z", native=False)
    def isConnectedOrConnecting(self, emu):
        return self.__isConnected


class WifiConfiguration(
    metaclass=JavaClassDef,
    jvm_name="android/net/wifi/WifiConfiguration",
    jvm_fields=[
        JavaFieldDef("SSID", "Ljava/lang/String;", False),
        JavaFieldDef("hiddenSSID", "Z", False),
        JavaFieldDef("BSSID", "Ljava/lang/String;", False),
        JavaFieldDef("FQDN", "Ljava/lang/String;", False),
        JavaFieldDef("networkId", "I", False),
        JavaFieldDef("priority", "I", False),
        JavaFieldDef("providerFriendlyName", "Ljava/lang/String;", False),
    ],
):
    def __init__(self):
        self.SSID = String("")
        self.BSSID = String("")
        self.FQDN = String("")
        self.hiddenSSID = False
        self.networkId = 0
        self.priority = 0
        self.providerFriendlyName = String("hello")


class DhcpInfo(
    metaclass=JavaClassDef,
    jvm_name="android/net/DhcpInfo",
    jvm_fields=[
        JavaFieldDef("gateway", "I", False),
    ],
):
    def __init__(self):
        self.gateway = 0


class WifiManager(metaclass=JavaClassDef, jvm_name="android/net/wifi/WifiManager"):
    def __init__(self):
        self.__list = List([])
        self.__dhcpInfo = DhcpInfo()

    @java_method_def(
        name="getConfiguredNetworks",
        signature="()Ljava/util/List;",
        native=False,
    )
    def getConfiguredNetworks(self, emu):
        return self.__list

    @java_method_def(
        name="getDhcpInfo", signature="()Landroid/net/DhcpInfo;", native=False
    )
    def getDhcpInfo(self, emu):
        return self.__dhcpInfo

    @java_method_def(name="getDeviceId", signature="()Ljava/lang/String;", native=False)
    def getDeviceId(self, emu, *args, **kwargs):
        val = emu.config.get("device_id", "12345678")
        return String(val)

    @java_method_def(
        name="getSubscriberId", signature="()Ljava/lang/String;", native=False
    )
    def getSubscriberId(self, emu, *args, **kwargs):
        val = emu.config.get("subscriber_id", "12345678")
        return String(val)

    @java_method_def(
        name="getConnectionInfo",
        signature="()Landroid/net/wifi/WifiInfo;",
        native=False,
    )
    def getConnectionInfo(self, *args, **kwargs):
        return WifiInfo()


class RequestBuilder(
    metaclass=JavaClassDef, jvm_name="android/net/NetworkRequest$Builder"
):
    def __init__(self):
        pass

    @java_method_def(name="<init>", signature="()V", native=False)
    def init(self, *args, **kwargs):
        return RequestBuilder()

    @java_method_def(
        name="addTransportType",
        signature="(I)Landroid/net/NetworkRequest$Builder;",
        native=False,
    )
    def addTransportType(self, emu, i):
        return RequestBuilder()
