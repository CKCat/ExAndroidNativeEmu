from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
import time


class SystemClock(
    Object, metaclass=JavaClassDef, jvm_name="android/os/SystemClock", jvm_super=Object
):
    def __init__(self):
        Object.__init__(self)

    # Start time for emulation
    _start_time = time.time()
    _perf_start = time.perf_counter()

    @staticmethod
    @java_method_def(name="uptimeMillis", signature="()J", native=False)
    def uptimeMillis(emu):
        # time since boot, not counting sleep.
        # For emulation, just use elapsed time since module start
        diff = time.perf_counter() - SystemClock._perf_start
        return int(diff * 1000)

    @staticmethod
    @java_method_def(name="elapsedRealtime", signature="()J", native=False)
    def elapsedRealtime(emu):
        # time since boot, including sleep.
        # Same as uptime for us
        return SystemClock.uptimeMillis(emu)

    @staticmethod
    @java_method_def(name="currentThreadTimeMillis", signature="()J", native=False)
    def currentThreadTimeMillis(emu):
        # In python, maybe process time?
        return int(time.process_time() * 1000)

    @staticmethod
    @java_method_def(name="sleep", args_list=["jlong"], signature="(J)V", native=False)
    def sleep(emu, ms):
        time.sleep(ms / 1000.0)
