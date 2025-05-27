from loguru import logger

from .helpers.native_method import native_method
from .jni_const import JNI_OK
from .jni_env import JNIEnv


# https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/invocation.html
# This class attempts to mimic the JNIInvokeInterface table.
class JavaVM:
    """
    :type class_loader JavaClassLoader
    :type hooker Hooker
    """

    def __init__(self, emu, class_loader, hooker):
        """_summary_

        Args:
            emu (_type_): _description_
            class_loader (_type_): JavaClassLoader
            hooker (_type_): Hooker
        """
        (self.address_ptr, self.address) = hooker.write_function_table(
            {
                3: self.destroy_java_vm,
                4: self.attach_current_thread,
                5: self.detach_current_thread,
                6: self.get_env,
                7: self.attach_current_thread,
            }
        )

        self.jni_env = JNIEnv(emu, class_loader, hooker)
        self.__emu = emu

    @native_method
    def destroy_java_vm(self, mu):
        raise NotImplementedError()

    @native_method
    def attach_current_thread(self, mu, java_vm, env_ptr, thr_args):
        logger.debug(
            f"JavaVM->AttachCurrentThread(0x{java_vm:08x}, 0x{env_ptr:08x}, 0x{thr_args:08x})"
        )
        mu.mem_write(
            env_ptr,
            self.jni_env.address_ptr.to_bytes(
                self.__emu.get_ptr_size(), byteorder="little"
            ),
        )
        return JNI_OK

    @native_method
    def detach_current_thread(self, mu, java_vm):
        # TODO: NooOO idea.
        logger.debug(f"JavaVM->DetachCurrentThread(0x{java_vm:08x})")
        return JNI_OK

    @native_method
    def get_env(self, mu, java_vm, env_ptr, version):
        logger.debug(
            f"JavaVM->GetEnv(0x{java_vm:08x}, 0x{env_ptr:08x}, 0x{version:08x})"
        )
        mu.mem_write(
            env_ptr,
            self.jni_env.address_ptr.to_bytes(
                self.__emu.get_ptr_size(), byteorder="little"
            ),
        )
        return JNI_OK

    @native_method
    def attach_current_thread_as_daemon(self, mu, java_vm, env_ptr, thr_args):
        logger.debug(
            f"JavaVM->AttachCurrentThreadAsDaemon(0x{java_vm:08x}, 0x{env_ptr:08x}, 0x{thr_args:08x})"
        )
        mu.mem_write(
            env_ptr,
            self.jni_env.address_ptr.to_bytes(
                self.__emu.get_ptr_size(), byteorder="little"
            ),
        )
        return JNI_OK
