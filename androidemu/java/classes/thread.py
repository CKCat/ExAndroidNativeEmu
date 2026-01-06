from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from loguru import logger


class Thread(
    Object, metaclass=JavaClassDef, jvm_name="java/lang/Thread", jvm_super=Object
):
    def __init__(self):
        Object.__init__(self)
        self.__runnable = None
        self.__name = "Thread-0"

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        pass

    @java_method_def(
        name="<init>",
        args_list=["jobject"],
        signature="(Ljava/lang/Runnable;)V",
        native=False,
    )
    def ctor_runnable(self, emu, runnable):
        self.__runnable = runnable

    @java_method_def(name="start", signature="()V", native=False)
    def start(self, emu):
        logger.debug(f"Thread {self.__name} starting...")
        # Synchronous execution for now to assume simpler emulation model
        self.run(emu)

    @java_method_def(name="run", signature="()V", native=False)
    def run(self, emu):
        if self.__runnable:
            # Call Runnable.run()
            # We need to find the run method on the runnable object
            # This requires JNI-like method lookup or assuming Python implementation
            # For now, let's try to call 'run' on the python object if it exists.

            # Assuming runnable is a PyObject wrapper of the Java object
            run_method = self.__runnable.__class__.find_method("run", "()V")
            if run_method:
                run_method.func(self.__runnable, emu)
            else:
                logger.warning(
                    "Thread started with Runnable but run() method not found."
                )

    @staticmethod
    @java_method_def(
        name="currentThread", signature="()Ljava/lang/Thread;", native=False
    )
    def currentThread(emu):
        # Return a dummy main thread or the current one if we track it
        t = Thread()
        t.__name = "main"
        return t

    @java_method_def(
        name="getStackTrace", signature="()[Ljava/lang/StackTraceElement;", native=False
    )
    def getStackTrace(self, emu):
        # Return empty array for now
        return None
