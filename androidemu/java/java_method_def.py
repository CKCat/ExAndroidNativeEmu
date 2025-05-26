from __future__ import annotations

import sys

from loguru import logger

from ..const import emu_const
from .constant_values import JAVA_NULL
from .java_class_def import JavaClassDef
from .jni_ref import jclass, jobject
from .jvm_id_conter import next_method_id


class JavaMethodDef:
    def __init__(
        self,
        func_name: str,
        func: callable,
        name: str,
        signature: str,
        native: bool = False,
        args_list=None,
        modifier=None,
        ignore=None,
    ):
        self.jvm_id = next_method_id()
        self.func_name = func_name
        self.func = func
        self.name = name
        self.signature = signature
        self.native = native
        self.native_addr = None
        self.args_list = args_list
        self.modifier = modifier
        self.ignore = ignore


def java_method_def(
    name: str,
    signature: str,
    native: bool = False,
    args_list=None,
    modifier=None,
    ignore: bool = False,
):
    """装饰器，用于注册 Java 方法"""

    def java_method_def_real(func: callable):
        """func的包装器

        Args:
            func (callable): 被装饰的函数
        """

        def native_wrapper(*args, **kwargs):
            """native 方法的包装器"""
            clz: object = args[0].__class__
            emulator = None
            extra_args: list = None
            first_obj = 0xFA
            if isinstance(clz, JavaClassDef):
                # 如果第一个参数是 Java 类，则是 self
                emulator = args[1]
                extra_args = args[2:]

                # 将 self 转为 this object 的引用，传入 jni 第一个参数
                first_obj = emulator.java_vm.jni_env.add_local_reference(
                    jobject(args[0])
                )
            else:
                # 否则是static方法
                emulator = args[0]
                extra_args = args[1:]
                # static 方法第一个参数为 jclass，想办法找到对应的 pyclass 然后转成 jclass 的引用
                # 利用装饰前的函数全名找所在的python类
                vals = vars(sys.modules[func.__module__])
                logger.debug(f"vars {vals}")
                sa = func.__qualname__.split(".")
                # 一层层迭代取类，防止函数在嵌套的类里面
                for attr in sa[:-1]:
                    vals = vals[attr]

                pyclazz: object = vals
                if not isinstance(pyclazz, JavaClassDef):
                    raise RuntimeError(
                        f"Error class {pyclazz} is not register as jvm class!!!"
                    )

                jvm_clazz = pyclazz.class_object
                # 如果是 static 的，第一个参数是 jclass 引用
                first_obj = emulator.java_vm.jni_env.add_local_reference(
                    jclass(jvm_clazz)
                )

            brace_index = signature.find(")")
            if brace_index < 0:
                raise RuntimeError(
                    f"native_wrapper invalid function signature {signature}."
                )

            return_index = brace_index + 1
            return_ch = signature[return_index]
            res = None
            arch = emulator.get_arch()
            if return_ch in ("J", "D") and arch == emu_const.ARCH_ARM32:
                # 返回值是 jlong 或者 jdouble ,在32位下需要读取两个寄存器
                res = emulator.call_native_return_2reg(
                    native_wrapper.jvm_method.native_addr,
                    emulator.java_vm.jni_env.address_ptr,  # JNIEnv*
                    first_obj,  # this object or this class
                    # method has been declared in
                    *extra_args,  # Extra args.
                )
            else:
                res = emulator.call_native(
                    native_wrapper.jvm_method.native_addr,
                    emulator.java_vm.jni_env.address_ptr,  # JNIEnv*
                    first_obj,  # this object or this class
                    # method has been declared in
                    *extra_args,  # Extra args.
                )

            r = None
            if return_ch in ("[", "L"):
                # 返回值是 object 的话,需要转换 jniref 到真实 object ,方便使用
                result_idx = res
                result = emulator.java_vm.jni_env.get_local_reference(result_idx)
                if result is None:
                    r = JAVA_NULL
                else:
                    r = result.value

            else:
                # 基本类型的话直接返回
                r = res

            # jni 规格,从 native 层退出需要清除所有 jni 引用
            emulator.java_vm.jni_env.clear_locals()
            return r

        def normal_wrapper(*args, **kwargs):
            """普通 Java 方法的包装器直接调用原方法"""
            result = func(*args, **kwargs)
            return result

        wrapper = native_wrapper if native else normal_wrapper

        wrapper.jvm_method = JavaMethodDef(
            func.__name__,
            wrapper,
            name,
            signature,
            native,
            args_list=args_list,
            modifier=modifier,
            ignore=ignore,
        )
        return wrapper

    return java_method_def_real
