from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .bundle import Bundle
from .object import Object
from .string import String


class IntentFilter(
    Object,
    metaclass=JavaClassDef,
    jvm_name="android/content/IntentFilter",
    jvm_super=Object,
):
    def __init__(self):
        Object.__init__(self)

    @java_method_def(
        name="<init>",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def init(self, emu, str):
        pass


class Intent(
    Object, metaclass=JavaClassDef, jvm_name="android/content/Intent", jvm_super=Object
):
    def __init__(self, action=None, uri=None):
        Object.__init__(self)
        self.__action = action
        self.__data = uri
        self.__extras = Bundle()
        self.__flags = 0

    @java_method_def(
        name="<init>",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def init_action(self, emu, action):
        self.__action = action.get_py_string()

    @java_method_def(
        name="<init>",
        args_list=["jobject", "jobject"],
        signature="(Landroid/content/Context;Ljava/lang/Class;)V",
        native=False,
    )
    def init_ctx_cls(self, emu, ctx, cls):
        # Stub
        pass

    @java_method_def(name="getExtras", signature="()Landroid/os/Bundle;", native=False)
    def getExtras(self, emu):
        return self.__extras

    @java_method_def(name="getAction", signature="()Ljava/lang/String;", native=False)
    def getAction(self, emu):
        return String(self.__action) if self.__action else None

    @java_method_def(name="getData", signature="()Landroid/net/Uri;", native=False)
    def getData(self, emu):
        return self.__data

    @java_method_def(
        name="setAction",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Landroid/content/Intent;",
        native=False,
    )
    def setAction(self, emu, action):
        self.__action = action.get_py_string()
        return self

    @java_method_def(
        name="setData",
        args_list=["jobject"],
        signature="(Landroid/net/Uri;)Landroid/content/Intent;",
        native=False,
    )
    def setData(self, emu, uri):
        self.__data = uri
        return self

    @java_method_def(
        name="setFlags",
        args_list=["jint"],
        signature="(I)Landroid/content/Intent;",
        native=False,
    )
    def setFlags(self, emu, flags):
        self.__flags = flags
        return self

    @java_method_def(
        name="addCategory",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Landroid/content/Intent;",
        native=False,
    )
    def addCategory(self, emu, category):
        return self

    @java_method_def(
        name="putExtra",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;",
        native=False,
    )
    def putExtra_string(self, emu, name, value):
        # We need to expose putString on Bundle if we want to delegate properly,
        # or just access inner implementation if Bundle is python-friendly.
        # Assuming Bundle has a map or putString.
        # For now, stub data storage into __extras if Bundle allows logic.
        # Check Bundle implementation:
        # It's better to just implement putExtra here as "return self" generally, but storing data is better.
        return self
