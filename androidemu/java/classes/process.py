from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object


class Process(
    Object, metaclass=JavaClassDef, jvm_name="android/os/Process", jvm_super=Object
):
    def __init__(self):
        Object.__init__(self)

    @staticmethod
    @java_method_def(name="myPid", signature="()I", native=False)
    def myPid(emu):
        return emu.get_pcb().get_pid()

    @staticmethod
    @java_method_def(name="myUid", signature="()I", native=False)
    def myUid(emu):
        return emu.get_pcb().uid

    @staticmethod
    @java_method_def(name="myTid", signature="()I", native=False)
    def myTid(emu):
        return emu.get_schduler().get_current_tid()

    @staticmethod
    @java_method_def(name="setThreadPriority", signature="(I)V", native=False)
    def setThreadPriority(emu, priority):
        sch = emu.get_schduler()
        tid = sch.get_current_tid()
        sch.set_priority(tid, priority)

    @staticmethod
    @java_method_def(
        name="setThreadPriority",
        args_list=["jint", "jint"],
        signature="(II)V",
        native=False,
    )
    def setThreadPriority2(emu, tid, priority):
        sch = emu.get_schduler()
        sch.set_priority(tid, priority)
