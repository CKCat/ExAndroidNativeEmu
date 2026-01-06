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


# ================= 辅助工具 =================
def print_hex(name, data):
    """模拟 Unidbg 的 Inspector.inspect"""
    hex_str = binascii.hexlify(data).decode("utf-8")
    # 每32个字符(16字节)换行，简单的格式化
    formatted = ""
    for i in range(0, len(hex_str), 32):
        chunk = hex_str[i : i + 32]
        formatted += chunk + "\n"
    print(f"[{name}] len={len(data)}\n{formatted}")


# ================= 1. 定义 Java 类结构 =================
class Utilities(metaclass=JavaClassDef, jvm_name="org/telegram/messenger/Utilities"):
    def __init__(self):
        pass

    # 注册 Native 方法签名
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


class TelegramSignTest:
    def __init__(self):
        # 初始化模拟器
        self.emulator = Emulator(vfp_inst_set=True)
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

        # 加载基础系统库 (请确保目录下有 vfs/system/lib/)
        self.emulator.load_library("libc.so")
        self.emulator.load_library("libstdc++.so")
        self.emulator.load_library("libm.so")
        self.emulator.load_library("libdl.so")
        self.emulator.load_library("liblog.so")

        # Telegram 的 so 可能依赖 libjnigraphics，如果没有该文件，可能会报错
        # 视情况加载，或忽略(如果 SO 是懒加载)
        try:
            self.emulator.load_library("libjnigraphics.so")
        except:
            print("警告: 未找到 libjnigraphics.so，继续执行...")

        # 加载目标库
        lib_path = "tests/bin/libtmessages.29.so"
        print(f"正在加载 {lib_path}...")
        try:
            self.lib_module = self.emulator.load_library(lib_path)
        except Exception as e:
            print(f"加载库失败: {e}")
            sys.exit(1)

        # AndroidNativeEmu 默认不自动调用 JNI_OnLoad，需要手动调用
        self.emulator.call_symbol(
            self.lib_module, "JNI_OnLoad", self.emulator.java_vm.address_ptr, 0x00
        )

        self.clazz_name = "org/telegram/messenger/Utilities"

    def get_native_addr(self, method_name):
        """获取注册后的 Native 函数地址"""
        # 1. 尝试从已注册的动态 native 方法中查找
        for method in self.emulator.java_classloader.find_class_by_name(
            self.clazz_name
        ).jvm_methods.values():
            if method.name == method_name and method.native_addr:
                return method.native_addr

        # 2. 尝试查找静态导出的 JNI 符号
        # 规则: Java_package_class_method
        # org.telegram.messenger.Utilities -> Java_org_telegram_messenger_Utilities_
        mangle_name = "Java_" + self.clazz_name.replace("/", "_") + "_" + method_name
        # 处理下划线等特殊字符，如果有的话（这里假设暂时没有或者简单替换）
        # JNI 规范: _ -> _1, ; -> _2, [ -> _3

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

        # 构造 JNI 对象
        jni_env = self.emulator.java_vm.jni_env
        j_data = jni_env.add_local_reference(jobject(ByteArray(list(data))))
        j_key = jni_env.add_local_reference(jobject(ByteArray(list(key))))
        j_iv = jni_env.add_local_reference(jobject(ByteArray(list(iv))))

        # 获取函数地址
        func_addr = self.get_native_addr("aesCbcEncryptionByteArray")
        if not func_addr:
            print("未找到函数地址!")
            return

        # 调用 Native: static void (JNIEnv*, jclass, jbyteArray, jbyteArray, jbyteArray, int, int, int, int)
        self.emulator.call_native(
            func_addr,
            jni_env.address_ptr,
            0x1234,  # jclass
            j_data,  # data
            j_key,  # key
            j_iv,  # iv
            0,  # offset
            len(data),  # length
            0,  # fileOffset
            0,  # fileLength
        )

        # 获取结果 (因为是引用传递，修改反映在 j_data 对象内部)
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

        # static void (JNIEnv*, jclass, jbyteArray, jbyteArray, jbyteArray, int, int, int)
        self.emulator.call_native(
            func_addr, jni_env.address_ptr, 0x1234, j_data, j_key, j_iv, 0, len(data), 0
        )

        result_data = jni_env.get_local_reference(j_data).value
        cost = (time.time() - start_time) * 1000
        print_hex(
            f"aesCtrDecryptionByteArray 耗时={cost:.2f}ms", bytearray(result_data)
        )

    def pbkdf2(self):
        print("\n=== 测试 pbkdf2 ===")

        password = b"123456"
        salt = bytearray(8)
        # 目标 buffer
        dst = bytearray(64)

        jni_env = self.emulator.java_vm.jni_env

        # 循环测试3次
        for i in range(3):
            start_time = time.time()

            # 每次调用前，如果需要重置数据可以在这里做
            # 注意：如果多次调用，JNI 引用可以复用，但在 Python 脚本里重新创建比较清晰
            j_pass = jni_env.add_local_reference(jobject(ByteArray(list(password))))
            j_salt = jni_env.add_local_reference(jobject(ByteArray(list(salt))))
            j_dst = jni_env.add_local_reference(jobject(ByteArray(list(dst))))

            func_addr = self.get_native_addr("pbkdf2")

            # static void (JNIEnv*, jclass, jbyteArray, jbyteArray, jbyteArray, int)
            self.emulator.call_native(
                func_addr,
                jni_env.address_ptr,
                0x1234,
                j_pass,
                j_salt,
                j_dst,
                100000,  # iterations
            )

            result_data = jni_env.get_local_reference(j_dst).value
            cost = (time.time() - start_time) * 1000
            print_hex(f"pbkdf2 耗时={cost:.2f}ms", bytearray(result_data))


if __name__ == "__main__":
    # 设置日志输出
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)

    test = TelegramSignTest()
    test.aesCbcEncryptionByteArray()
    test.aesCtrDecryptionByteArray()
    test.pbkdf2()
