import time
from loguru import logger
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from ...const.java_const import JAVA_NULL
from .string import String


class System(metaclass=JavaClassDef, jvm_name="java/lang/System"):
    def __init__(self):
        pass

    @staticmethod
    @java_method_def(
        name="getProperty",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/String;",
        native=False,
    )
    def getProperty(emu, key_obj):
        key = key_obj.get_py_string()
        if key in emu.system_properties:
            return String(emu.system_properties[key])

        # Fallback or special handling if needed
        if key == "java.vm.version":
            return String("1.6.0")

        return String("")

    @staticmethod
    @java_method_def(name="currentTimeMillis", signature="()J", native=False)
    def currentTimeMillis(emu):
        return int(time.time() * 1000)

    @staticmethod
    @java_method_def(name="nanoTime", signature="()J", native=False)
    def nanoTime(emu):
        return int(time.perf_counter_ns())

    @staticmethod
    @java_method_def(
        name="arraycopy",
        args_list=["jobject", "jint", "jobject", "jint", "jint"],
        signature="(Ljava/lang/Object;ILjava/lang/Object;II)V",
        native=False,
    )
    def arraycopy(emu, src, srcPos, dest, destPos, length):
        # src and dest should be Array objects
        # We need to access their internal python list/array

        # Warning: This direct access assumes src/dest are our Array python wrappers.
        # If they are just python lists wrapped on the fly, it might be different.
        # But java.lang.Object is passed, so they are likely our wrapper objects.

        src_items = src.get_py_items()
        dest_items = dest.get_py_items()

        # Python slice assignment
        dest_items[destPos : destPos + length] = src_items[srcPos : srcPos + length]

    @staticmethod
    @java_method_def(
        name="loadLibrary",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def loadLibrary(emu, libname):
        py_libname = libname.get_py_string()
        logger.info(
            f"System.loadLibrary({py_libname}) called. Ignoring (assuming pre-loaded)."
        )
        # In the future, we could actually trigger module loading here.

    @staticmethod
    @java_method_def(
        name="identityHashCode",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)I",
        native=False,
    )
    def identityHashCode(emu, obj):
        if obj is None or obj == JAVA_NULL:
            return 0
        return id(obj)
