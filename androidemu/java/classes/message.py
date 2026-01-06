from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from ..java_field_def import JavaFieldDef
from .object import Object
from .bundle import Bundle


class Message(
    Object, metaclass=JavaClassDef, jvm_name="android/os/Message", jvm_super=Object
):
    def __init__(self):
        Object.__init__(self)
        self.what = 0
        self.arg1 = 0
        self.arg2 = 0
        self.obj = None
        self.__data = None

    @staticmethod
    @java_method_def(name="obtain", signature="()Landroid/os/Message;", native=False)
    def obtain(emu):
        return Message()

    @java_method_def(name="getData", signature="()Landroid/os/Bundle;", native=False)
    def getData(self, emu):
        if self.__data is None:
            self.__data = Bundle()
        return self.__data

    @java_method_def(
        name="setData",
        args_list=["Landroid/os/Bundle;"],
        signature="(Landroid/os/Bundle;)V",
        native=False,
    )
    def setData(self, emu, data):
        self.__data = data

    # Define public fields
    what = JavaFieldDef("what", "I", False)
    arg1 = JavaFieldDef("arg1", "I", False)
    arg2 = JavaFieldDef("arg2", "I", False)
    obj = JavaFieldDef("obj", "Ljava/lang/Object;", False)
