from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def


class AccessibilityManager(
    metaclass=JavaClassDef,
    jvm_name="android/view/accessibility/AccessibilityManager",
):
    def __init__(self):
        pass

    @java_method_def(
        name="getEnabledAccessibilityServiceList",
        args_list=["jint"],
        signature="(I)Ljava/util/List;",
        native=False,
    )
    def getEnabledAccessibilityServiceList(self, emu, i):
        from .list import List

        return List([])


class AccessibilityInteractionController(
    metaclass=JavaClassDef,
    jvm_name="android/view/AccessibilityInteractionController",
):
    def __init__(self):
        pass
