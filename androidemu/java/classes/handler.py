from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .looper import Looper
from loguru import logger


class Handler(
    Object, metaclass=JavaClassDef, jvm_name="android/os/Handler", jvm_super=Object
):
    def __init__(self, looper=None):
        Object.__init__(self)
        self.__looper = (
            looper if looper else Looper(main=True)
        )  # Default to some looper

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        self.__looper = Looper.getMainLooper(emu)

    @java_method_def(
        name="<init>",
        args_list=["Landroid/os/Looper;"],
        signature="(Landroid/os/Looper;)V",
        native=False,
    )
    def ctor_looper(self, emu, looper):
        self.__looper = looper

    @java_method_def(
        name="sendMessage",
        args_list=["Landroid/os/Message;"],
        signature="(Landroid/os/Message;)Z",
        native=False,
    )
    def sendMessage(self, emu, msg):
        return self.sendMessageDelayed(emu, msg, 0)

    @java_method_def(
        name="sendMessageDelayed",
        args_list=["Landroid/os/Message;", "jlong"],
        signature="(Landroid/os/Message;J)Z",
        native=False,
    )
    def sendMessageDelayed(self, emu, msg, delayMillis):
        # Stub: Log and maybe call handleMessage immediately for simple emulation
        logger.debug(
            f"Handler sendMessageDelayed: what={getattr(msg, 'what', '?')} delay={delayMillis}"
        )
        # Simplification: Invoke handleMessage directly?
        # In real Android, this goes to MessageQueue.
        # For simple crypto/logic emulation, we might just drop it or execute immediately if logic depends on it.
        # Let's execute handleMessage immediately for now (synchronous emulation)
        self.handleMessage(emu, msg)
        return True

    @java_method_def(
        name="handleMessage",
        args_list=["Landroid/os/Message;"],
        signature="(Landroid/os/Message;)V",
        native=False,
    )
    def handleMessage(self, emu, msg):
        # To be overridden by subclass or python implementation
        pass

    @java_method_def(
        name="post",
        args_list=["Ljava/lang/Runnable;"],
        signature="(Ljava/lang/Runnable;)Z",
        native=False,
    )
    def post(self, emu, runnable):
        logger.debug("Handler post runnable")
        # Execute runnable 'run' method?
        # We need to know how to invoke 'run' on the runnable object (which might be a Proxy or implemented class)
        # Assuming runnable has 'run' method.
        # runnable.run(emu) # This would need JNI call semantic if it's a java object.
        # For now just log.
        return True

    @java_method_def(
        name="postDelayed",
        args_list=["Ljava/lang/Runnable;", "jlong"],
        signature="(Ljava/lang/Runnable;J)Z",
        native=False,
    )
    def postDelayed(self, emu, runnable, delayMillis):
        logger.debug(f"Handler postDelayed runnable delay={delayMillis}")
        return True

    @java_method_def(name="getLooper", signature="()Landroid/os/Looper;", native=False)
    def getLooper(self, emu):
        return self.__looper
