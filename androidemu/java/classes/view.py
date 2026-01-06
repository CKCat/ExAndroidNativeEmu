from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def
from .accessibility import AccessibilityInteractionController


class ViewRootImpl(
    metaclass=JavaClassDef,
    jvm_name="android/view/ViewRootImpl",
    jvm_fields=[
        JavaFieldDef(
            "mAccessibilityInteractionController",
            "android/view/AccessibilityInteractionController",
            False,
        )
    ],
):
    def __init__(self):
        self.mAccessibilityInteractionController = AccessibilityInteractionController()


class AttachInfo(
    metaclass=JavaClassDef,
    jvm_name="android/view/View$AttachInfo",
    jvm_fields=[JavaFieldDef("mViewRootImpl", "android/view/ViewRootImpl", False)],
):
    def __init__(self, view_root_impl):
        self.mViewRootImpl = view_root_impl


class View(
    metaclass=JavaClassDef,
    jvm_name="android/view/View",
    jvm_fields=[JavaFieldDef("", "android/view/View$AttachInfo", False)],
):
    def __init__(self):
        self.mAttachInfo = AttachInfo(ViewRootImpl())


class Window(metaclass=JavaClassDef, jvm_name="android/view/Window"):
    def __init__(self):
        self.__dec_view = View()

    @java_method_def(
        name="getDecorView", signature="()Landroid/view/View;", native=False
    )
    def getDecorView(self, emu):
        return self.__dec_view
