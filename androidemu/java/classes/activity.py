from ..classes.context import ContextWrapper
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .view import Window


class Activity(
    ContextWrapper,
    metaclass=JavaClassDef,
    jvm_name="android/app/Activity",
    jvm_super=ContextWrapper,
):
    def __init__(self):
        ContextWrapper.__init__(self)
        self.__window = Window()

    @java_method_def(
        name="getWindow", signature="()Landroid/view/Window;", native=False
    )
    def getWindow(self, emu):
        return self.__window

    @java_method_def(
        name="getApplication",
        signature="()Landroid/app/Application;",
        native=False,
    )
    def getApplication(self, emu):
        from .activity_thread import ActivityThread

        return ActivityThread.currentApplication(emu)
