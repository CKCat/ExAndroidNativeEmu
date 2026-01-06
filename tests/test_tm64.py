import logging
import sys
import time
import binascii
from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.java.classes.array import ByteArray
from androidemu.java.classes.string import String
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.jni_ref import jobject
from androidemu.const import emu_const


# ================= 辅助工具：Hex Dump =================
def print_hex(name, data):
    hex_str = binascii.hexlify(data).decode("utf-8")
    formatted = ""
    # 每32个字符(16字节)换行
    for i in range(0, len(hex_str), 32):
        chunk = hex_str[i : i + 32]
        formatted += chunk + " "
    print(f"[{name}] len={len(data)}\n{formatted}")


# ================= 1. 定义 Java 类: Utilities =================
class Utilities(metaclass=JavaClassDef, jvm_name="org/telegram/messenger/Utilities"):
    def __init__(self):
        pass

    # 注册 Native 方法签名 (与 Java 代码一致)

    # public static native void aesCbcEncryptionByteArray(byte[] data, byte[] key, byte[] iv, int offset, int length, int fileOffset, int fileLength);
    @java_method_def(
        name="aesCbcEncryptionByteArray", signature="([B[B[BIIII)V", native=True
    )
    def aesCbcEncryptionByteArray(self, mu):
        pass

    # public static native void aesCtrDecryptionByteArray(byte[] data, byte[] key, byte[] iv, int offset, int length, int fileOffset);
    @java_method_def(
        name="aesCtrDecryptionByteArray", signature="([B[B[BIII)V", native=True
    )
    def aesCtrDecryptionByteArray(self, mu):
        pass

    # public static native void pbkdf2(byte[] password, byte[] salt, byte[] dst, int iterations);
    @java_method_def(name="pbkdf2", signature="([B[B[BI)V", native=True)
    def pbkdf2(self, mu):
        pass


# ================= 2. 辅助类定义 (Stub) =================
class QuickAckDelegate(
    metaclass=JavaClassDef, jvm_name="org/telegram/tgnet/QuickAckDelegate"
):
    def __init__(self):
        pass

    @java_method_def(name="run", signature="()V", native=False)
    def run(self, emu):
        pass


class RequestTimeDelegate(
    metaclass=JavaClassDef, jvm_name="org/telegram/tgnet/RequestTimeDelegate"
):
    def __init__(self):
        pass

    @java_method_def(name="run", signature="(J)V", native=False)
    def run(self, emu, time):
        pass


class RequestDelegateInternal(
    metaclass=JavaClassDef,
    jvm_name="org/telegram/tgnet/RequestDelegateInternal",
):
    def __init__(self):
        pass

    @java_method_def(name="run", signature="(JILjava/lang/String;I)V", native=False)
    def run(self, emu, response, errorCode, errorText, networkType):
        pass


class ConnectionsManager(
    metaclass=JavaClassDef, jvm_name="org/telegram/tgnet/ConnectionsManager"
):
    def __init__(self):
        pass

    @java_method_def(
        name="onUnparsedMessageReceived",
        signature="(JI)V",
        native=False,
        args_list=["jlong", "jint"],
    )
    def onUnparsedMessageReceived(self, emu, native_ptr, type):
        pass

    @java_method_def(
        name="onUpdate",
        signature="(I)V",
        native=False,
        args_list=["jint"],
    )
    def onUpdate(self, emu, type):
        pass

    @java_method_def(
        name="onSessionCreated",
        signature="(I)V",
        native=False,
        args_list=["jint"],
    )
    def onSessionCreated(self, emu, type):
        pass

    @java_method_def(
        name="onLogout",
        signature="(I)V",
        native=False,
        args_list=["jint"],
    )
    def onLogout(self, emu, type):
        pass

    @java_method_def(
        name="onConnectionStateChanged",
        signature="(II)V",
        native=False,
        args_list=["jint", "jint"],
    )
    def onConnectionStateChanged(self, emu, state, type):
        pass

    @java_method_def(
        name="onBytesSent",
        signature="(III)V",
        native=False,
        args_list=["jint", "jint", "jint"],
    )
    def onBytesSent(self, emu, amount, networkType, type):
        pass

    @java_method_def(
        name="onBytesReceived",
        signature="(III)V",
        native=False,
        args_list=["jint", "jint", "jint"],
    )
    def onBytesReceived(self, emu, amount, networkType, type):
        pass

    @java_method_def(
        name="onRequestNewServerIpAndPort",
        signature="(II)V",
        native=False,
        args_list=["jint", "jint"],
    )
    def onRequestNewServerIpAndPort(self, emu, second, type):
        pass

    @java_method_def(
        name="onProxyError",
        signature="()V",
        native=False,
    )
    def onProxyError(self, emu):
        pass

    @java_method_def(
        name="onGetConfig",
        signature="(I)V",
        native=False,
        args_list=["jint"],
    )
    def onGetConfig(self, emu, type):
        pass

    @java_method_def(
        name="getHostByName",
        signature="(Ljava/lang/String;I)Ljava/lang/String;",
        native=False,
        args_list=["jstring", "jint"],
    )
    def getHostByName(self, emu, domain, type):
        return String("127.0.0.1")

    @java_method_def(
        name="getInitFlags",
        signature="()I",
        native=False,
    )
    def getInitFlags(self, emu):
        return 0

    @java_method_def(
        name="onInternalPushReceived",
        signature="(I)V",
        native=False,
        args_list=["jint"],
    )
    def onInternalPushReceived(self, emu, type):
        pass

    @java_method_def(
        name="onUpdateConfig",
        signature="(JI)V",
        native=False,
        args_list=["jlong", "jint"],
    )
    def onUpdateConfig(self, emu, ptr, type):
        pass


class NativeByteBuffer(
    metaclass=JavaClassDef, jvm_name="org/telegram/tgnet/NativeByteBuffer"
):
    def __init__(self):
        pass


class VoIPController(
    metaclass=JavaClassDef, jvm_name="org/telegram/messenger/voip/VoIPController"
):
    nativeInst = JavaFieldDef("nativeInst", "J", False)

    def __init__(self):
        pass


class VoIPGroupController(
    metaclass=JavaClassDef, jvm_name="org/telegram/messenger/voip/VoIPGroupController"
):
    nativeInst = JavaFieldDef("nativeInst", "J", False)

    def __init__(self):
        pass


class AudioRecordJNI(
    metaclass=JavaClassDef, jvm_name="org/telegram/messenger/voip/AudioRecordJNI"
):
    nativeInst = JavaFieldDef("nativeInst", "J", False)

    def __init__(self):
        pass


class AudioTrackJNI(
    metaclass=JavaClassDef, jvm_name="org/telegram/messenger/voip/AudioTrackJNI"
):
    nativeInst = JavaFieldDef("nativeInst", "J", False)

    def __init__(self):
        pass


class VoIPServerConfig(
    metaclass=JavaClassDef, jvm_name="org/telegram/messenger/voip/VoIPServerConfig"
):
    def __init__(self):
        pass


class Resampler(
    metaclass=JavaClassDef, jvm_name="org/telegram/messenger/voip/Resampler"
):
    def __init__(self):
        pass


class VideoRenderer(
    metaclass=JavaClassDef, jvm_name="org/telegram/messenger/voip/VideoRenderer"
):
    def __init__(self):
        pass


class VideoSource(
    metaclass=JavaClassDef, jvm_name="org/telegram/messenger/voip/VideoSource"
):
    def __init__(self):
        pass


class WriteToSocketDelegate(
    metaclass=JavaClassDef, jvm_name="org/telegram/tgnet/WriteToSocketDelegate"
):
    def __init__(self):
        pass

    @java_method_def(name="run", signature="()V", native=False)
    def run(self, emu):
        pass


class FileLoadOperationDelegate(
    metaclass=JavaClassDef, jvm_name="org/telegram/tgnet/FileLoadOperationDelegate"
):
    def __init__(self):
        pass

    @java_method_def(name="onFinished", signature="(Ljava/lang/String;)V", native=False)
    def onFinished(self, emu, path):
        pass

    @java_method_def(
        name="onFailed", signature="(I)V", native=False, args_list=["jint"]
    )
    def onFailed(self, emu, reason):
        pass

    @java_method_def(name="onProgressChanged", signature="(F)V", native=False)
    def onProgressChanged(self, emu, progress):
        pass


class FilesToDelete(
    metaclass=JavaClassDef, jvm_name="org/telegram/messenger/FileLoader$FileResolver"
):
    def __init__(self):
        pass


# ================= 3. 主逻辑 =================
class Utilities64Test:
    def __init__(self):
        # 初始化模拟器，指定为 64位 (arm64)
        print("初始化模拟器 (ARM64)...")
        self.emulator = Emulator(arch=emu_const.ARCH_ARM64)

        # 注册 Java 类
        self.emulator.java_classloader.add_class(Utilities)
        self.emulator.java_classloader.add_class(NativeByteBuffer)
        self.emulator.java_classloader.add_class(ConnectionsManager)
        self.emulator.java_classloader.add_class(RequestDelegateInternal)
        self.emulator.java_classloader.add_class(RequestTimeDelegate)
        self.emulator.java_classloader.add_class(QuickAckDelegate)
        self.emulator.java_classloader.add_class(WriteToSocketDelegate)
        self.emulator.java_classloader.add_class(FileLoadOperationDelegate)
        self.emulator.java_classloader.add_class(VideoRenderer)
        self.emulator.java_classloader.add_class(VideoSource)
        self.emulator.java_classloader.add_class(VoIPController)
        self.emulator.java_classloader.add_class(VoIPGroupController)
        self.emulator.java_classloader.add_class(AudioRecordJNI)
        self.emulator.java_classloader.add_class(AudioTrackJNI)
        self.emulator.java_classloader.add_class(VoIPServerConfig)
        self.emulator.java_classloader.add_class(Resampler)

        # 加载 64位 系统库
        # 使用默认 vfs_root，自动从 system/lib64/ 加载
        try:
            self.emulator.load_library("libc.so")
            self.emulator.load_library("libstdc++.so")
            self.emulator.load_library("libm.so")
            self.emulator.load_library("libdl.so")
            self.emulator.load_library("liblog.so")
        except Exception as e:
            print(f"加载系统库失败: {e}")
            print("请确保 vfs/system/lib64/ 下存在 libc.so 等 64位 系统库文件")
            sys.exit(1)

        # 加载目标库 (arm64-v8a)
        lib_path = "tests/bin64/libtmessages.29.so"
        print(f"正在加载 {lib_path}...")
        try:
            self.lib_module = self.emulator.load_library(lib_path)
        except Exception as e:
            print(f"加载目标库失败: {e}")
            sys.exit(1)

        # 手动调用 JNI_OnLoad
        self.emulator.call_symbol(
            self.lib_module, "JNI_OnLoad", self.emulator.java_vm.address_ptr, 0x00
        )

        self.clazz_name = "org/telegram/messenger/Utilities"

    def get_native_addr(self, method_name):
        """从 ClassDef 中查找注册后的 Native 函数地址"""
        # 1. 尝试从已注册的动态 native 方法中查找
        for method in self.emulator.java_classloader.find_class_by_name(
            self.clazz_name
        ).jvm_methods.values():
            if method.name == method_name and method.native_addr:
                return method.native_addr

        # 2. 尝试查找静态导出的 JNI 符号
        # 规则: Java_package_class_method
        mangle_name = "Java_" + self.clazz_name.replace("/", "_") + "_" + method_name

        # 简单查找
        sym = self.emulator.modules.find_symbol_str(mangle_name)
        if sym:
            return sym

        return None

    def aesCbcEncryptionByteArray(self):
        print("\n=== 测试 aesCbcEncryptionByteArray ===")
        start_time = time.time()

        # 准备数据
        data = bytearray(16)  # new byte[16]
        key = bytearray(32)  # new byte[32]
        iv = bytearray(16)  # new byte[16]

        jni_env = self.emulator.java_vm.jni_env

        # 创建 JNI 对象引用
        j_data = jni_env.add_local_reference(jobject(ByteArray(list(data))))
        j_key = jni_env.add_local_reference(jobject(ByteArray(list(key))))
        j_iv = jni_env.add_local_reference(jobject(ByteArray(list(iv))))

        func_addr = self.get_native_addr("aesCbcEncryptionByteArray")
        if not func_addr:
            print("Refunc address not found (Registration failed?)")
            return

        # 参数: (JNIEnv*, jclass, data, key, iv, offset, length, fileOffset, fileLength)
        self.emulator.call_native(
            func_addr,
            jni_env.address_ptr,
            0xCAFEBABE,  # jclass (mock)
            j_data,
            j_key,
            j_iv,
            0,  # offset
            len(data),  # length
            0,  # fileOffset
            0,  # fileLength
        )

        # 获取修改后的数据
        result_data = jni_env.get_local_reference(j_data).value

        cost = (time.time() - start_time) * 1000
        print_hex(
            f"aesCbcEncryptionByteArray 耗时={cost:.2f}ms", bytearray(result_data)
        )

    def aesCtrDecryptionByteArray(self):
        print("\n=== 测试 aesCtrDecryptionByteArray ===")
        start_time = time.time()

        data = bytearray(16)
        key = bytearray(32)
        iv = bytearray(16)

        jni_env = self.emulator.java_vm.jni_env
        j_data = jni_env.add_local_reference(jobject(ByteArray(list(data))))
        j_key = jni_env.add_local_reference(jobject(ByteArray(list(key))))
        j_iv = jni_env.add_local_reference(jobject(ByteArray(list(iv))))

        func_addr = self.get_native_addr("aesCtrDecryptionByteArray")

        # 参数: (JNIEnv*, jclass, data, key, iv, offset, length, fileOffset)
        self.emulator.call_native(
            func_addr,
            jni_env.address_ptr,
            0xCAFEBABE,
            j_data,
            j_key,
            j_iv,
            0,
            len(data),
            0,
        )

        result_data = jni_env.get_local_reference(j_data).value

        cost = (time.time() - start_time) * 1000
        print_hex(
            f"[arm64] aesCtrDecryptionByteArray 耗时={cost:.2f}ms",
            bytearray(result_data),
        )

    def pbkdf2(self):
        print("\n=== 测试 pbkdf2 ===")

        password = b"123456"
        salt = bytearray(8)

        jni_env = self.emulator.java_vm.jni_env
        func_addr = self.get_native_addr("pbkdf2")

        for i in range(3):
            start_time = time.time()
            dst = bytearray(64)  # 每次循环重置输出 buffer

            j_pass = jni_env.add_local_reference(jobject(ByteArray(list(password))))
            j_salt = jni_env.add_local_reference(jobject(ByteArray(list(salt))))
            j_dst = jni_env.add_local_reference(jobject(ByteArray(list(dst))))

            # 参数: (JNIEnv*, jclass, password, salt, dst, iterations)
            self.emulator.call_native(
                func_addr,
                jni_env.address_ptr,
                0xCAFEBABE,
                j_pass,
                j_salt,
                j_dst,
                100000,  # iterations
            )

            result_data = jni_env.get_local_reference(j_dst).value
            cost = (time.time() - start_time) * 1000
            print_hex(f"pbkdf2 耗时={cost:.2f}ms", bytearray(result_data))


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)

    # 实例化测试类
    test = Utilities64Test()

    # 执行测试
    test.pbkdf2()
    test.aesCbcEncryptionByteArray()
    test.aesCtrDecryptionByteArray()
