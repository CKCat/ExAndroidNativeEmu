import logging
import sys
import time
from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.java.classes.string import String
from androidemu.java.jni_ref import jobject


# ================= 1. 定义 Java 类结构 =================
# 对应 Java 代码中的 com.kanxue.test2.MainActivity
class MainActivity(metaclass=JavaClassDef, jvm_name="com/kanxue/test2/MainActivity"):
    def __init__(self):
        pass

    # 注册 Native 方法
    # 对应: public native boolean jnitest(String str);
    @java_method_def(name="jnitest", signature="(Ljava/lang/String;)Z", native=True)
    def jnitest(self, mu):
        pass


# ================= 2. 主逻辑 =================
class KXCrackTest:
    def __init__(self):
        # 初始化模拟器 (默认 ARM32)
        print("初始化模拟器 (ARM32)...")
        self.emulator = Emulator(vfp_inst_set=True)

        # 载入基础系统库
        try:
            self.emulator.load_library("libc.so")
            self.emulator.load_library("libstdc++.so")
            self.emulator.load_library("libm.so")
            self.emulator.load_library("libdl.so")
            self.emulator.load_library("liblog.so")
        except Exception as e:
            print(f"载入系统库失败: {e}")
            sys.exit(1)

        # 注册 Java 类
        self.emulator.java_classloader.add_class(MainActivity)

        # 载入目标 SO 文件
        lib_path = "tests/bin/libnative-lib-kx.so"
        print(f"正在加载 {lib_path}...")
        try:
            self.lib_module = self.emulator.load_library(lib_path)
        except Exception as e:
            print(f"加载目标库失败: {e}")
            sys.exit(1)

        self.clazz_name = "com/kanxue/test2/MainActivity"

    def get_native_addr(self, method_name):
        """获取 Native 函数地址 (支持动态注册和静态导出)"""
        # 1. 尝试从已注册的动态 native 方法中查找
        for method in self.emulator.java_classloader.find_class_by_name(
            self.clazz_name
        ).jvm_methods.values():
            if method.name == method_name and method.native_addr:
                return method.native_addr

        # 2. 尝试查找静态导出的 JNI 符号
        # 规则: Java_Package_Class_Method
        mangle_name = "Java_" + self.clazz_name.replace("/", "_") + "_" + method_name
        sym = self.emulator.modules.find_symbol_str(mangle_name)
        if sym:
            return sym

        return None

    def run_crack(self):
        print("\n=== 开始验证 jnitest ===")
        start_time = time.time()

        # 获取函数地址
        func_addr = self.get_native_addr("jnitest")
        if not func_addr:
            print("未找到 jnitest 函数地址!")
            return

        print(f"找到 Native 函数地址: 0x{func_addr:x}")

        jni_env = self.emulator.java_vm.jni_env
        # 模拟 jobject (MainActivity instance)
        # 0x12345678 是一个伪造的指针，只要 native 方法不反向调用该对象的实例方法即可
        thiz_ptr = 0x12345678

        # 测试输入
        test_inputs = ["abc", "xyz", "AAA", "XuE"]

        for input_str in test_inputs:
            # 构造 jstring
            str_jobject = jobject(String(input_str))
            jstring_ref = jni_env.add_local_reference(str_jobject)

            # 调用 Native 函数
            # 签名: (JNIEnv*, jobject, jstring)
            res = self.emulator.call_native(
                func_addr, jni_env.address_ptr, thiz_ptr, jstring_ref
            )

            # 打印结果
            result_bool = "True" if res == 1 else "False"
            print(f"jnitest('{input_str}') = {res} ({result_bool})")

        elapsed = (time.time() - start_time) * 1000
        print(f"测试完成，耗时: {elapsed:.2f}ms")


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)

    test = KXCrackTest()
    test.run_crack()
