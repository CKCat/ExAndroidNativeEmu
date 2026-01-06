# ExAndroidNativeEmu 使用指南

**ExAndroidNativeEmu** 是一个基于 Unicorn 引擎的 Android Native 代码模拟框架，旨在 PC 上运行和分析 Android ELF (so) 文件。它是 [AndroidNativeEmu](https://github.com/AeonLucid/AndroidNativeEmu) 的增强版本，增加了对多线程、JNI 反射、ARM64 以及更完善的内存管理支持。

本指南将详细介绍如何安装、配置以及编写测试用例来模拟执行 Android Native 代码。

---

## 目录

1.  [环境准备](#1-环境准备)
2.  [快速开始](#2-快速开始)
3.  [核心概念与用法](#3-核心概念与用法)
    - [初始化模拟器](#31-初始化模拟器)
    - [定义 Java 类 (JNI Bridge)](#32-定义-java-类-jni-bridge)
    - [加载 SO 库](#33-加载-so-库)
    - [调用 Native 函数](#34-调用-native-函数)
    - [JNI 交互与回调](#35-jni-交互与回调)
4.  [进阶功能](#4-进阶功能)
    - [Hook Native 函数](#41-hook-native-函数)
    - [文件系统模拟](#42-文件系统模拟)
    - [多架构支持 (ARM32/ARM64)](#43-多架构支持-arm32arm64)
5.  [常见问题排查](#5-常见问题排查)

---

## 1. 环境准备

确保你的 Python 版本 >= 3.7。

1.  **克隆仓库**

    ```bash
    git clone https://github.com/vkeynew/ExAndroidNativeEmu.git
    cd ExAndroidNativeEmu
    ```

2.  **安装依赖**

    ```bash
    pip install -r requirements.txt
    ```

    _主要依赖包括 `unicorn`, `keystone-engine`, `capstone` 等。_

3.  **准备环境文件**
    确保 `androidemu/data/vfs/system/lib` (ARM32) 或 `lib64` (ARM64) 目录下包含 Android 系统基础库（如 `libc.so`, `libm.so`, `libdl.so`, `liblog.so`, `libstdc++.so`）。

---

## 2. 快速开始

创建一个简单的脚本 `demo.py` 来加载并运行一个 JNI 函数。

```python
import logging
import sys
from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def

# 1. 定义一个 Java 类供 Native 代码调用 (可选，视 SO 依赖而定)
class MainActivity(metaclass=JavaClassDef, jvm_name='com/example/test/MainActivity'):
    def __init__(self):
        pass

    @java_method_def(name='stringFromJNI', signature='()Ljava/lang/String;', native=True)
    def string_from_jni(self, mu):
        pass

# 2. 设置日志
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)

# 3. 初始化模拟器
emulator = Emulator(vfp_inst_set=True) # vfp_inst_set=True 启用 VFP 指令集支持

# 4. 注册 Java 类
emulator.java_classloader.add_class(MainActivity)

# 5. 加载系统库 (按顺序)
emulator.load_library("libc.so")
emulator.load_library("libstdc++.so")
emulator.load_library("libm.so")
emulator.load_library("libdl.so")
emulator.load_library("liblog.so")

# 6. 加载目标 SO 库
lib_module = emulator.load_library("tests/bin/libnative-lib.so")

# 7. 触发 JNI_OnLoad (如果存在)
emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0)

# 8. 调用 Native 方法
# 方式 A: 通过 Java 类实例调用 (推荐，模拟更完整)
# 需要先实例化 Java 对象
main_activity = MainActivity()
# TODO: 通过 emulator 调用 Java 方法的接口

# 方式 B: 直接调用 Native 地址 (Unidbg 风格)
# 假设我们知道 Java_com_example_test_MainActivity_stringFromJNI 的符号或地址
# 需要手动构造 JNIEnv 指针等参数
```

_(注：更详细的调用示例见下文 "调用 Native 函数")_

---

## 3. 核心概念与用法

### 3.1 初始化模拟器

```python
from androidemu.emulator import Emulator
from androidemu.const import emu_const

# ARM32 (默认)
emulator = Emulator(vfp_inst_set=True)

# ARM64
emulator = Emulator(arch=emu_const.ARCH_ARM64)
```

### 3.2 定义 Java 类 (JNI Bridge)

为了让 Native 代码能够调用 Java 层的方法（即 CallIntMethod, GetStaticFieldID 等），你需要用 Python 模拟对应的 Java 类。

使用 `JavaClassDef` 元类和 `@java_method_def` 装饰器。

```python
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.java.java_field_def import JavaFieldDef

class Utils(metaclass=JavaClassDef, jvm_name='com/example/Utils'):
    def __init__(self):
        pass

    # 定义字段
    someField = JavaFieldDef("someField", "I", is_static=False) # I = int

    # 定义普通方法
    # signature: JNI 签名
    # native=False: 表示这是一个 Java 方法，由 Python 实现供 Native 调用
    @java_method_def(name='getTimestamp', signature='()J', native=False)
    def get_timestamp(self, emu):
        import time
        return int(time.time() * 1000)

    # 定义 Native 方法 (即 SO 中实现的方法)
    # native=True: 表示这是一个 Native 方法
    @java_method_def(name='encrypt', signature='([B)[B', native=True)
    def encrypt(self, emu):
        pass
```

### 3.3 加载 SO 库

```python
# 加载基础库
emulator.load_library("libc.so")

# 加载你的目标库
# load_library 会自动处理依赖加载 (如果 VFS 中存在依赖库)
lib_module = emulator.load_library("path/to/libtarget.so")

# 获取模块基址
print(f"Loaded at 0x{lib_module.base:X}")
```

### 3.4 调用 Native 函数

有两种主要方式调用 Native 函数。

#### 方法一：通过 `call_symbol` (调用导出函数)

适用于调用 `JNI_OnLoad` 或其他非 JNI 标准导出的 C 函数。

```python
# 参数: 模块对象, 函数名, 参数1, 参数2, ...
emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0)
```

#### 方法二：通过 `call_native` (底层调用)

最灵活的方式，适用于调用 JNI 函数（需要手动传 `JNIEnv*`）。

```python
from androidemu.java.jni_ref import jobject
from androidemu.java.classes.string import String

# 1. 获取函数地址
# 方式 A: 如果是动态注册的函数，从 ClassLoader 获取
method = emulator.java_classloader.find_class_by_name("com/example/Utils").find_method("encrypt", "([B)[B")
func_addr = method.native_addr

# 方式 B: 如果是静态导出的 JNI 函数，通过符号查找
func_addr = emulator.modules.find_symbol_str("Java_com_example_Utils_encrypt")

# 2. 准备 JNI 参数
jni_env = emulator.java_vm.jni_env
# 构造一个 Java String 对象并转为引用
j_str = jobject(String("Hello World"))
j_str_ref = jni_env.add_local_reference(j_str)

# 3. 调用
# JNI 函数前两个参数固定为: JNIEnv*, jobject/jclass
emulator.call_native(
    func_addr,              # 函数地址
    jni_env.address_ptr,    # JNIEnv*
    0,                      # jobject/jclass (This 指针，静态方法传 class，实例方法传 object)
    j_str_ref               # 参数 1
)

# 4. 获取返回值
# 如果返回值是 jobject，需要通过 local ref 获取 python 对象
result_ref = ... # 从调用结果获取 (注意 return 值处理)
# 注意：call_native 本身不直接返回 Python 对象，需要根据 ABI 约定读取寄存器，
# 或者使用 helper 封装。ExAndroidNativeEmu 目前通常需要手动处理返回值，或者在 Native 方法 hook 中处理。
```

_(提示：查看 `tests/test_tm.py` 中的 `aesCbcEncryptionByteArray` 方法，了解如何完整处理 `byte[]` 参数的传递和结果获取)_

### 3.5 JNI 交互与回调

当 Native 代码调用 Java 方法时（例如 `env->CallObjectMethod`），框架会自动分发到你定义的 Python 类中。

**处理数组参数：**
如果 Native 方法修改了传入的 `byte[]` 数组，Python 侧如何获取修改后的值？
ExAndroidNativeEmu 实现了 `ReleasePrimitiveArrayElements` 的写回逻辑。只需确保使用 JNI 提供的引用对象。

```python
data = bytearray([0, 0, 0, 0])
j_data = jni_env.add_local_reference(jobject(ByteArray(list(data))))

# 调用 Native ...

# 获取结果
# 框架会自动更新 ByteArray 内部的数据
result_data = jni_env.get_local_reference(j_data).value
print(result_data)
```

---

## 4. 进阶功能

### 4.1 Hook Native 函数

你可以 Hook 任意 Native 地址来拦截执行、查看参数或修改返回值。

```python
from unicorn.arm_const import UC_ARM_REG_R0

def my_hook(emu):
    # 读取参数 (ARM32: R0-R3)
    arg0 = emu.mu.reg_read(UC_ARM_REG_R0)
    print(f"Hooked! arg0={arg0}")

    # 可以在这里修改寄存器或内存

# 注册 Hook
# 参数: 地址, 回调函数
emulator.mu.hook_add(UC_HOOK_CODE,
                     lambda mu, address, size, user_data: my_hook(emulator),
                     begin=target_addr, end=target_addr)
```

ExAndroidNativeEmu 还提供了更高级的 Hook 封装（参考 `androidemu/hooker.py`）。

### 4.2 文件系统模拟 (`VFS`)

模拟器虚拟了一个简单的文件系统，根目录在 `androidemu/data/vfs`。
你可以将 APK 中的 assets 或其他文件放入该目录，以便 Native 代码通过 `open()` 读取。

- `androidemu/data/vfs/system/lib` -> `/system/lib`
- `androidemu/data/vfs/data/local/tmp` -> `/data/local/tmp`

### 4.3 多架构支持 (ARM32/ARM64)

框架支持无缝切换 ARM32 和 ARM64。

- ARM32: 指针 4 字节，库在 `/system/lib`。
- ARM64: 指针 8 字节，库在 `/system/lib64`。

编写测试脚本时，注意根据架构选择不同的库路径和 `Emulator` 初始化参数。

---

## 5. 常见问题排查

**Q: `RuntimeError: Emulator not found in args`**
A: 这通常是因为内部代码调用了被 `@native_method` 装饰的函数。请检查调用栈，确保使用 `_set_pending_exception` 等内部方法替代直接调用 JNI 接口。

**Q: 执行结果全是 0 或空?**
A: 检查是否是通过数组传递数据的。如果是，确保 JNI 层正确触发了 `ReleaseByteArrayElements` (模式非 JNI_ABORT)，并且框架已包含数据写回的修复补丁。

**Q: `Register native ... failed`**
A: 模拟器无法找到对应的 Java 方法签名。请检查 `JavaClassDef` 中定义的签名是否与 SO 中 `RegisterNatives` 调用的签名完全一致（包括参数类型和返回类型）。

**Q: 找不到符号 `Undefined external symbol`**
A: 缺少依赖库。检查 SO 依赖了哪些系统库，并将它们放入 `vfs/system/lib` 目录，并在脚本中显式 `load_library`。

**Q: `UC_ERR_READ_UNMAPPED`**
A: 发生了非法内存访问。

1. 可能是空指针解引用。
2. 可能是传入 Native 函数的指针（如 JNIEnv, jobject）不正确。
3. 可能是栈溢出或堆损坏。
   开启 `logging.DEBUG` 查看崩溃前的指令和 syscall 日志。
