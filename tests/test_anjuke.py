import logging
import sys
from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.java.classes.array import ByteArray
from androidemu.java.classes.map import HashMap
from androidemu.java.classes.string import String
from androidemu.java.jni_ref import jobject


# ================= 1. 定义目标类 =================
# com.anjuke.mobile.sign.SignUtil
class SignUtil(metaclass=JavaClassDef, jvm_name="com/anjuke/mobile/sign/SignUtil"):
    def __init__(self):
        pass

    # 注册 Native 方法签名
    # public static native String getSign0(String p1, String p2, Map map, String p3, int i);
    @java_method_def(
        name="getSign0",
        signature="(Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;I)Ljava/lang/String;",
        native=True,
    )
    def getSign0(self, mu):
        pass


# ================= 2. 主逻辑 =================
class AnjukeSignTest:
    def __init__(self):
        # 初始化模拟器 (默认 ARM32)
        print("初始化模拟器 (ARM32)...")
        self.emulator = Emulator(vfp_inst_set=True)

        # 加载基础库
        try:
            self.emulator.load_library("libc.so")
            self.emulator.load_library("libstdc++.so")
            self.emulator.load_library("libm.so")
            self.emulator.load_library("libdl.so")
        except Exception as e:
            print(f"载入系统库失败: {e}")
            sys.exit(1)

        # 注册 Java 类 (HashMap 已内置)
        self.emulator.java_classloader.add_class(SignUtil)

        # 加载目标 SO
        lib_path = "tests/bin/libsignutil.so"
        print(f"正在加载 {lib_path}...")
        try:
            self.lib_module = self.emulator.load_library(lib_path)
        except Exception as e:
            print(f"加载目标库失败: {e}")
            sys.exit(1)

        self.clazz_name = "com/anjuke/mobile/sign/SignUtil"

    def get_native_addr(self, method_name):
        """获取 Native 函数地址"""
        # 1. 动态注册查找
        for method in self.emulator.java_classloader.find_class_by_name(
            self.clazz_name
        ).jvm_methods.values():
            if method.name == method_name and method.native_addr:
                return method.native_addr

        # 2. 静态符号查找
        mangle_name = "Java_" + self.clazz_name.replace("/", "_") + "_" + method_name
        sym = self.emulator.modules.find_symbol_str(mangle_name)
        if sym:
            return sym

        return None

    def run_sign(self):
        print("\n=== 开始测试 getSign0 ===")

        # 1. 准备基本参数
        p1_str = "aa"
        p2_str = "bb"
        p3_str = "cc"
        i_val = 10

        # 2. 准备 Map 参数 (模拟 Unidbg 行为：Map<String, byte[]> )
        param_map_data = {"a": "b", "b": "b"}
        java_map = HashMap()

        for k, v in param_map_data.items():
            # key: String
            key_str = String(k)
            # value: byte[] (from string utf-8 bytes)
            byte_data = list(v.encode("utf-8"))
            byte_array = ByteArray(byte_data)
            java_map[key_str] = byte_array

        # 3. 获取 Native 地址
        func_addr = self.get_native_addr("getSign0")
        if not func_addr:
            print("未找到 getSign0 函数地址")
            return

        print(f"调用 Native 函数地址: 0x{func_addr:x}")

        # 4. 构造 JNI 调用环境
        jni_env = self.emulator.java_vm.jni_env

        # 转换参数为 Local Reference
        jp1 = jni_env.add_local_reference(jobject(String(p1_str)))
        jp2 = jni_env.add_local_reference(jobject(String(p2_str)))
        jp3 = jni_env.add_local_reference(jobject(String(p3_str)))

        # java_map 是 JavaClassDef 实例，add_local_reference 会自动处理吗？
        # 目前 androidemu 的 add_local_reference 支持 JavaClassDef 实例
        # jmap_ref = jni_env.add_local_reference(jobject(java_map))
        # 或者直接传实例，call_native 会尝试转换?
        # 最稳妥是手动 add_local_reference
        # 注意：HashMap 继承自 Object，可以直接传给 jobject
        jmap_ref = jni_env.add_local_reference(jobject(java_map))

        # 5. 执行 Native 调用
        # 签名: (JNIEnv*, jclass, jstring, jstring, jobject(Map), jstring, jint)
        jclazz_mock = 0x12345

        result_idx = self.emulator.call_native(
            func_addr,
            jni_env.address_ptr,  # JNIEnv*
            jclazz_mock,  # jclass (static method)
            jp1,
            jp2,
            jmap_ref,
            jp3,
            i_val,
        )

        # 6. 解析结果
        if result_idx:
            result_obj = jni_env.get_local_reference(result_idx)
            if result_obj:
                print(f"签名结果: {result_obj.value}")
            else:
                print("获取结果对象失败")
        else:
            print("Native 返回结果为空 (NULL)")


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    test = AnjukeSignTest()
    test.run_sign()
