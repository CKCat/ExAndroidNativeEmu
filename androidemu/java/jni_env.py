from loguru import logger
import sys
from unicorn import UC_PROT_READ, UC_PROT_WRITE

from androidemu.hooker import Hooker
from androidemu.java.java_classloader import JavaClassLoader

from ..const import emu_const
from ..utils import memory_helpers
from .classes.array import (
    Array,
    ByteArray,
)
from .classes.byte_buffer import DirectByteBuffer
from .classes.constructor import Constructor
from .classes.method import Method
from .classes.string import String
from ..const.java_const import JAVA_NULL, MODIFIER_STATIC
from ..const.jni_const import JNI_FALSE, JNI_OK, JNI_TRUE
from ..java.helpers.native_method import native_method
from .jni_ref import jclass, jobject
from .reference_table import ReferenceTable
from ..java.helpers.valist import (
    get_next_float_arg64,
    get_next_int_arg64,
)


# 这个类用于模拟 JNINativeInterface 表。
class JNIEnv:
    def __init__(self, emu, class_loader: JavaClassLoader, hooker: Hooker):
        self._emu = emu
        self._class_loader = class_loader
        self._locals = ReferenceTable(start=1, max_entries=2048)
        self._globals = ReferenceTable(start=4096, max_entries=512000000)
        arch = emu.get_arch()
        if arch == emu_const.ARCH_ARM32:
            self.__read_args = self.__read_args32
            self.__read_args_v = self.__read_args_v32
        elif arch == emu_const.ARCH_ARM64:
            self.__read_args = self.__read_args64
            self.__read_args_v = self.__read_args_v64
        else:
            raise NotImplementedError(f"unsupport arch {arch}")

        self._local_frame_stack = []  # Stack of list of indices [ [idx1, idx2], [idx3] ]

        self._exception = None  # Store pending exception object (jobject or None)

        (self.address_ptr, self.address) = hooker.write_function_table(
            {
                4: self.get_version,
                5: self.define_class,
                6: self.find_class,
                7: self.from_reflected_method,
                8: self.from_reflected_field,
                9: self.to_reflected_method,
                10: self.get_superclass,
                11: self.is_assignable_from,
                12: self.to_reflected_field,
                13: self.throw,
                14: self.throw_new,
                15: self.exception_occurred,
                16: self.exception_describe,
                17: self.exception_clear,
                18: self.fatal_error,
                19: self.push_local_frame,
                20: self.pop_local_frame,
                21: self.new_global_ref,
                22: self.delete_global_ref,
                23: self.delete_local_ref,
                24: self.is_same_object,
                25: self.new_local_ref,
                26: self.ensure_local_capacity,
                27: self.alloc_object,
                28: self.new_object,
                29: self.new_object_v,
                30: self.new_object_a,
                31: self.get_object_class,
                32: self.is_instance_of,
                33: self.get_method_id,
                34: self.call_object_method,
                35: self.call_object_method_v,
                36: self.call_object_method_a,
                37: self.call_boolean_method,
                38: self.call_boolean_method_v,
                39: self.call_boolean_method_a,
                40: self.call_byte_method,
                41: self.call_byte_method_v,
                42: self.call_byte_method_a,
                43: self.call_char_method,
                44: self.call_char_method_v,
                45: self.call_char_method_a,
                46: self.call_short_method,
                47: self.call_short_method_v,
                48: self.call_short_method_a,
                49: self.call_int_method,
                50: self.call_int_method_v,
                51: self.call_int_method_a,
                52: self.call_long_method,
                53: self.call_long_method_v,
                54: self.call_long_method_a,
                55: self.call_float_method,
                56: self.call_float_method_v,
                57: self.call_float_method_a,
                58: self.call_double_method,
                59: self.call_double_method_v,
                60: self.call_double_method_a,
                61: self.call_void_method,
                62: self.call_void_method_v,
                63: self.call_void_method_a,
                64: self.call_nonvirtual_object_method,
                65: self.call_nonvirtual_object_method_v,
                66: self.call_nonvirtual_object_method_a,
                67: self.call_nonvirtual_boolean_method,
                68: self.call_nonvirtual_boolean_method_v,
                69: self.call_nonvirtual_boolean_method_a,
                70: self.call_nonvirtual_byte_method,
                71: self.call_nonvirtual_byte_method_v,
                72: self.call_nonvirtual_byte_method_a,
                73: self.call_nonvirtual_char_method,
                74: self.call_nonvirtual_char_method_v,
                75: self.call_nonvirtual_char_method_a,
                76: self.call_nonvirtual_short_method,
                77: self.call_nonvirtual_short_method_v,
                78: self.call_nonvirtual_short_method_a,
                79: self.call_nonvirtual_int_method,
                80: self.call_nonvirtual_int_method_v,
                81: self.call_nonvirtual_int_method_a,
                82: self.call_nonvirtual_long_method,
                83: self.call_nonvirtual_long_method_v,
                84: self.call_nonvirtual_long_method_a,
                85: self.call_nonvirtual_float_method,
                86: self.call_nonvirtual_float_method_v,
                87: self.call_nonvirtual_float_method_a,
                88: self.call_nonvirtual_double_method,
                89: self.call_nonvirtual_double_method_v,
                90: self.call_nonvirtual_double_method_a,
                91: self.call_nonvirtual_void_method,
                92: self.call_nonvirtual_void_method_v,
                93: self.call_nonvirtual_void_method_a,
                94: self.get_field_id,
                95: self.get_object_field,
                96: self.get_boolean_field,
                97: self.get_byte_field,
                98: self.get_char_field,
                99: self.get_short_field,
                100: self.get_int_field,
                101: self.get_long_field,
                102: self.get_float_field,
                103: self.get_double_field,
                104: self.set_object_field,
                105: self.set_boolean_field,
                106: self.set_byte_field,
                107: self.set_char_field,
                108: self.set_short_field,
                109: self.set_int_field,
                110: self.set_long_field,
                111: self.set_float_field,
                112: self.set_double_field,
                113: self.get_static_method_id,
                114: self.call_static_object_method,
                115: self.call_static_object_method_v,
                116: self.call_static_object_method_a,
                117: self.call_static_boolean_method,
                118: self.call_static_boolean_method_v,
                119: self.call_static_boolean_method_a,
                120: self.call_static_byte_method,
                121: self.call_static_byte_method_v,
                122: self.call_static_byte_method_a,
                123: self.call_static_char_method,
                124: self.call_static_char_method_v,
                125: self.call_static_char_method_a,
                126: self.call_static_short_method,
                127: self.call_static_short_method_v,
                128: self.call_static_short_method_a,
                129: self.call_static_int_method,
                130: self.call_static_int_method_v,
                131: self.call_static_int_method_a,
                132: self.call_static_long_method,
                133: self.call_static_long_method_v,
                134: self.call_static_long_method_a,
                135: self.call_static_float_method,
                136: self.call_static_float_method_v,
                137: self.call_static_float_method_a,
                138: self.call_static_double_method,
                139: self.call_static_double_method_v,
                140: self.call_static_double_method_a,
                141: self.call_static_void_method,
                142: self.call_static_void_method_v,
                143: self.call_static_void_method_a,
                144: self.get_static_field_id,
                145: self.get_static_object_field,
                146: self.get_static_boolean_field,
                147: self.get_static_byte_field,
                148: self.get_static_char_field,
                149: self.get_static_short_field,
                150: self.get_static_int_field,
                151: self.get_static_long_field,
                152: self.get_static_float_field,
                153: self.get_static_double_field,
                154: self.set_static_object_field,
                155: self.set_static_boolean_field,
                156: self.set_static_byte_field,
                157: self.set_static_char_field,
                158: self.set_static_short_field,
                159: self.set_static_int_field,
                160: self.set_static_long_field,
                161: self.set_static_float_field,
                162: self.set_static_double_field,
                163: self.new_string,
                164: self.get_string_length,
                165: self.get_string_chars,
                166: self.release_string_chars,
                167: self.new_string_utf,
                168: self.get_string_utf_length,
                169: self.get_string_utf_chars,
                170: self.release_string_utf_chars,
                171: self.get_array_length,
                172: self.new_object_array,
                173: self.get_object_array_element,
                174: self.set_object_array_element,
                175: self.new_boolean_array,
                176: self.new_byte_array,
                177: self.new_char_array,
                178: self.new_short_array,
                179: self.new_int_array,
                180: self.new_long_array,
                181: self.new_float_array,
                182: self.new_double_array,
                183: self.get_boolean_array_elements,
                184: self.get_byte_array_elements,
                185: self.get_char_array_elements,
                186: self.get_short_array_elements,
                187: self.get_int_array_elements,
                188: self.get_long_array_elements,
                189: self.get_float_array_elements,
                190: self.get_double_array_elements,
                191: self.release_boolean_array_elements,
                192: self.release_byte_array_elements,
                193: self.release_char_array_elements,
                194: self.release_short_array_elements,
                195: self.release_int_array_elements,
                196: self.release_long_array_elements,
                197: self.release_float_array_elements,
                198: self.release_double_array_elements,
                199: self.get_boolean_array_region,
                200: self.get_byte_array_region,
                201: self.get_char_array_region,
                202: self.get_short_array_region,
                203: self.get_int_array_region,
                204: self.get_long_array_region,
                205: self.get_float_array_region,
                206: self.get_double_array_region,
                207: self.set_boolean_array_region,
                208: self.set_byte_array_region,
                209: self.set_char_array_region,
                210: self.set_short_array_region,
                211: self.set_int_array_region,
                212: self.set_long_array_region,
                213: self.set_float_array_region,
                214: self.set_double_array_region,
                215: self.register_natives,
                216: self.unregister_natives,
                217: self.monitor_enter,
                218: self.monitor_exit,
                219: self.get_java_vm,
                220: self.get_string_region,
                221: self.get_string_utf_region,
                222: self.get_primitive_array_critical,
                223: self.release_primitive_array_critical,
                224: self.get_string_critical,
                225: self.release_string_critical,
                226: self.new_weak_global_ref,
                227: self.delete_weak_global_ref,
                228: self.exception_check,
                229: self.new_direct_byte_buffer,
                230: self.get_direct_buffer_address,
                231: self.get_direct_buffer_capacity,
                232: self.get_object_ref_type,
            }
        )

    def get_reference(self, idx):
        if idx == 0:
            return None

        if self._locals.in_range(idx):
            return self._locals.get(idx)

        if self._globals.in_range(idx):
            return self._globals.get(idx)

        raise RuntimeError(f"Invalid get_reference({idx})")

    def add_local_reference(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")
        index = self._locals.add(obj)
        if self._local_frame_stack:
            self._local_frame_stack[-1].append(index)
        return index

    def set_local_reference(self, idx, newobj):
        if not isinstance(newobj, jobject):
            raise ValueError("Expected a jobject.")

        self._locals.set(idx, newobj)

    def get_local_reference(self, idx):
        r = self._locals.get(idx)
        return r

        # Look up index first? remove by obj is slow and doesn't give us index to remove from frame stack easily
        # But wait, ReferenceTable remove(obj) scans.
        # We need index to remove from stack.
        # Use reversed search or tracking?
        # Since ReferenceTable.remove(obj) returns True/False but not index, we can't easily know the index.
        # But JNIEnv usually deals with indices.
        # Wait, the JNI API is DeleteLocalRef(jobject localRef).
        # In this emulator 'localRef' IS the index (integer).
        # So 'obj' argument here IS the index.
        pass

    def delete_local_reference(self, idx):
        # idx is the local reference (int)
        if not isinstance(idx, int):
            raise ValueError("Expected an int index.")

        if idx == 0:
            return

        self._locals.remove_by_id(idx)

        # Remove from current frame stack if present
        if self._local_frame_stack:
            try:
                self._local_frame_stack[-1].remove(idx)
            except ValueError:
                pass

    def clear_locals(self):
        self._locals.clear()

    def add_global_reference(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        return self._globals.add(obj)

    def get_global_reference(self, idx):
        return self._globals.get(idx)

    def delete_global_reference(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")
        #
        return self._globals.remove(obj)

    # args is a tuple or list
    def __read_args32(self, mu, args, args_type_list):
        # 在这里处理八个字节参数问题，
        # 1.第一个参数为jlong jdouble 直接跳过列表第一个成员，因为第一个成员刚好是
        # call_xxx的第三个参数，根据调用约定，如果这个参数是8个字节，则直接跳过R3寄存器使用栈
        # 2.jlong或者jdouble需要两个arg成一个参数，对应用层透明
        if args_type_list is None:
            return []

        result = []
        args_index = 0
        n = len(args_type_list)
        nargs = len(args)
        args_list_index = 0
        while args_list_index < n:
            arg_name = args_type_list[args_list_index]
            if args_index == 0 and arg_name in ("jlong", "jdouble"):
                # 处理第一个参数(call_xxx第四个参数)跳过问题
                args_index = args_index + 1
                continue

            v = args[args_index]
            if arg_name in ("jint", "jchar", "jbyte", "jboolean"):
                result.append(v)

            elif arg_name in ("jlong", "jdouble"):
                args_index = args_index + 1
                if args_index >= nargs:
                    raise RuntimeError(
                        "read_args 在 args_type_list 上获取 long，但 args 长度不足以读取高字节"
                    )

                vh = args[args_index]
                value = (vh << 32) | v
                result.append(value)

            elif arg_name == "jstring" or arg_name == "jobject":
                ref = v
                jobj = self.get_reference(ref)
                obj = None
                if jobj is None:
                    logger.warning(
                        f"arg_name {arg_name} ref {ref} is not vaild maybe wrong arglist"
                    )
                    obj = JAVA_NULL
                else:
                    obj = jobj.value
                result.append(obj)
            else:
                raise NotImplementedError(f"Unknown arg name {arg_name}")
            args_index = args_index + 1
            args_list_index = args_list_index + 1

        return result

    def __read_args64(self, mu, args, args_type_list):
        # 64位情况简单得多，因为寄存器的大小为8字节，因此jlong，jdouble直接一个寄存器能装下，直接读即可
        if args_type_list is None:
            return []

        result = []
        n = len(args_type_list)
        logger.debug(f"args_type_list length {n}")
        nargs = len(args)

        for args_index in range(nargs):
            arg_name = args_type_list[args_index]
            v = args[args_index]
            if arg_name in (
                "jint",
                "jchar",
                "jbyte",
                "jboolean",
                "jlong",
                "jdouble",
            ):
                result.append(v)

            elif arg_name == "jstring" or arg_name == "jobject":
                ref = v
                jobj = self.get_reference(ref)
                obj = None
                if jobj is None:
                    logger.warning(
                        f"arg_name {arg_name} ref {ref} is not vaild maybe wrong arglist"
                    )
                    obj = JAVA_NULL
                else:
                    obj = jobj.value
                result.append(obj)
            else:
                raise NotImplementedError(f"Unknown arg name {arg_name}")

        return result

    def __read_args_v32(self, mu, args_ptr, args_type_list):
        result = []
        if args_type_list is None:
            return result

        for arg_name in args_type_list:
            # 使用指针 arg_ptr 的作为call_xxx_v第四个参数,不会出现跳过第四个参数的情况,因为arg_ptr总是四个字节
            v = int.from_bytes(mu.mem_read(args_ptr, 4), byteorder="little")
            if arg_name in ("jint", "jchar", "jbyte", "jboolean"):
                result.append(v)
            elif arg_name in ("jlong", "jdouble"):
                args_ptr = args_ptr + 4
                vh = int.from_bytes(mu.mem_read(args_ptr, 4), byteorder="little")
                value = (vh << 32) | v
                result.append(value)

            elif arg_name == "jstring" or arg_name == "jobject":
                ref = v
                jobj = self.get_reference(ref)
                obj = None
                if jobj is None:
                    logger.warning(
                        f"arg_name {arg_name} ref {ref} is not vaild maybe wrong arglist"
                    )
                    obj = JAVA_NULL
                else:
                    obj = jobj.value
                result.append(obj)
            else:
                raise NotImplementedError(f"Unknown arg name {arg_name}")

            args_ptr = args_ptr + 4

        return result

    def __read_args_v64(self, mu, args_ptr, args_type_list):
        result = []
        if not args_type_list:
            return result

        # args_ptr 指向 va_list 结构体
        va_list_addr = args_ptr

        for arg_name in args_type_list:
            # 注意：基本类型如 jint, jlong, jobject 在 ARM64 下都占用一个 64位通用寄存器槽位
            # 浮点类型(jfloat, jdouble) 使用 FP/SIMD 寄存器槽位 (__vr_offs)
            # 这里简化处理，假设所有参数都通过通用寄存器或栈传递
            # 如果涉及浮点参数，需要实现 get_next_float_arg64 使用 __vr_offs

            if arg_name in ("jfloat", "jdouble"):
                # 浮点参数在 FP 寄存器 (v0-v7) 中传递。
                # 使用 get_next_float_arg64 正确处理 VR 寄存器或栈
                is_double = arg_name == "jdouble"
                v = get_next_float_arg64(mu, va_list_addr, is_double)
                result.append(v)

            elif arg_name in ("jint", "jchar", "jbyte", "jboolean", "jshort"):
                v = get_next_int_arg64(mu, va_list_addr)
                # 符号扩展/截断通常由调用者处理，但 python 需要 int
                result.append(v & 0xFFFFFFFF)

            elif arg_name == "jlong":
                v = get_next_int_arg64(mu, va_list_addr)
                result.append(v)

            elif arg_name in ("jstring", "jobject"):
                ref = get_next_int_arg64(mu, va_list_addr)
                jobj = self.get_reference(ref)
                if jobj is None:
                    obj = JAVA_NULL
                else:
                    obj = jobj.value
                result.append(obj)
            else:
                # 数组类型
                ref = get_next_int_arg64(mu, va_list_addr)
                jobj = self.get_reference(ref)
                obj = jobj.value if jobj else JAVA_NULL
                result.append(obj)

        return result

    def __read_args_a(self, mu, args_ptr, args_type_list):
        result = []
        if not args_type_list:
            return result

        # args_ptr 指向 jvalue 联合体数组。
        # 32 位和 64 位上的 sizeof(jvalue) 均为 8 字节（因为 jdouble/jlong）。
        # 我们遍历 args_type_list，并且对于每个参数，我们读取下一个 8 字节槽。

        current_ptr = args_ptr
        for arg_name in args_type_list:
            # 读取 8 字节 (jvalue 大小)
            val_bytes = mu.mem_read(current_ptr, 8)
            val_int64 = int.from_bytes(val_bytes, byteorder="little")

            if arg_name in ("jint", "jchar", "jbyte", "jboolean", "jshort"):
                # < 32 位的基元通常位于低 4 个字节中
                # Python 需要 int，我们通常通过类型约束处理掩码，但 & 0xFFFFFFFF 对于 32 位视图是安全的
                result.append(val_int64 & 0xFFFFFFFF)

            elif arg_name == "jlong":
                result.append(val_int64)

            elif arg_name == "jfloat":
                # 需要将前 4 个字节解释为 float
                # val_int32 = val_int64 & 0xFFFFFFFF
                # 使用 struct 解包 float 会更干净，但这里我们模拟：
                # 在没有 struct 的情况下，我们无法轻松地将 int 位转换为 pure python 中的 float
                import struct

                f_val = struct.unpack("<f", val_bytes[:4])[0]
                result.append(f_val)

            elif arg_name == "jdouble":
                import struct

                d_val = struct.unpack("<d", val_bytes)[0]
                result.append(d_val)

            elif arg_name in ("jstring", "jobject"):
                # 指针通常是 32 位或 64 位，具体取决于架构，存储在 jvalue 中。
                # 如果是 32 位，则位于前 4 个字节中。
                ref = (
                    val_int64
                    if self._emu.get_arch() == emu_const.ARCH_ARM64
                    else (val_int64 & 0xFFFFFFFF)
                )
                jobj = self.get_reference(ref)
                obj = jobj.value if jobj else JAVA_NULL
                result.append(obj)
            else:
                # 数组是对象
                ref = (
                    val_int64
                    if self._emu.get_arch() == emu_const.ARCH_ARM64
                    else (val_int64 & 0xFFFFFFFF)
                )
                jobj = self.get_reference(ref)
                obj = jobj.value if jobj else JAVA_NULL
                result.append(obj)

            current_ptr += 8

        return result

    # arg_type = 0 元组或列表, 1 arg_v, 2 arg_a (jvalue*)
    def __read_args_common(self, mu, args, args_type_list, arg_type):
        if arg_type == 0:
            args_items = args
            return self.__read_args(mu, args_items, args_type_list)
        elif arg_type == 1:
            args_ptr = args
            return self.__read_args_v(mu, args_ptr, args_type_list)
        elif arg_type == 2:
            args_ptr = args
            return self.__read_args_a(mu, args_ptr, args_type_list)
        else:
            raise RuntimeError(f"arg_type {arg_type} not support")

    @staticmethod
    def jobject_to_pyobject(obj):
        if isinstance(obj, jobject):
            return obj.value
        else:
            raise RuntimeError(f"jobject_to_pyobject unknown obj type {obj}")

    @native_method
    def get_version(self, mu, env):
        logger.debug("JNIEnv->GetVersion() was called")
        return 65542

    @native_method
    def define_class(self, mu, env, name_ptr, loader_ref, buf_ptr, buf_len):
        # 桩实现
        name = memory_helpers.read_utf8(mu, name_ptr)
        logger.debug(f"JNIEnv->DefineClass({name}) (Stub) was called")
        return 0

    @native_method
    def find_class(self, mu, env, name_ptr):
        """
        根据完全限定名称返回类对象，如果找不到该类，则返回 NULL。
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        logger.debug(f"JNIEnv->FindClass({name}) was called")

        pyclazz = self._class_loader.find_class_by_name(name)
        if pyclazz is None:
            # 我们应该抛出 NoClassDefFoundError
            logger.warning(f"Could not find class '{name}' for JNIEnv.")
            self._set_pending_exception("java/lang/NoClassDefFoundError", name)
            return 0

        if pyclazz.jvm_ignore:
            logger.debug(f"FindClass {name} return 0 because of ignored")
            return 0

        # jclass包裹的都是Class的对象(Java Class Object)
        jvm_clazz = self._class_loader.get_class_object(pyclazz)
        return self.add_local_reference(jclass(jvm_clazz))

    @native_method
    def from_reflected_method(self, mu, env, method_obj_idx):
        """
        将 java.lang.reflect.Method or java.lang.reflect.Constructor 对象转换为方法 ID。
        """
        method_obj = self.get_reference(method_obj_idx)
        if method_obj is None:
            raise ValueError("Method object is NULL")

        if not isinstance(method_obj, jobject):
            raise ValueError("Expected a jobject for method_obj")

        py_method_obj = method_obj.value

        # 检查对象是否有获取方法ID的方法或属性
        if hasattr(py_method_obj, "get_method_id"):
            return py_method_obj.get_method_id()
        elif hasattr(py_method_obj, "jvm_method"):
            # 兼容旧的通过属性访问的方式
            return py_method_obj.jvm_method.jvm_id
        else:
            logger.warning(
                f"from_reflected_method: Object {py_method_obj} does not seem to have method ID accessor."
            )
            return 0

    @native_method
    def from_reflected_field(self, mu, env, field_obj_idx):
        """
        将 java.lang.reflect.Field 对象转换为字段 ID。
        """
        field_obj = self.get_reference(field_obj_idx)
        if field_obj is None:
            raise ValueError("Field object is NULL")

        py_field_obj = field_obj.value

        # 访问私有成员 _Field__field_def
        if (
            hasattr(py_field_obj, "_Field__field_def")
            and py_field_obj._Field__field_def
        ):
            return py_field_obj._Field__field_def.jvm_id

        logger.warning(
            f"from_reflected_field: Object {py_field_obj} does not seem to have field ID accessor."
        )
        return 0

    @native_method
    def to_reflected_method(self, mu, env, class_idx, method_id, is_static):
        """
        将源自 cls 的方法 ID 转换为 java.lang.reflect.Method 或 java.lang.reflect.Constructor 对象。
        如果方法 ID 引用静态方法，则必须将 isStatic 设置为 JNI_TRUE，否则设置为 JNI_FALSE。

        如果失败，则抛出 OutOfMemoryError 并返回 0。
        """
        clazz = self.get_reference(class_idx)

        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        method = pyclazz.find_method_by_id(method_id)
        if method is None:
            raise RuntimeError(
                f"Could not find method ('{method_id}') in class {pyclazz.jvm_name}."
            )

        if method.modifier & MODIFIER_STATIC:
            mu.mem_write(is_static, int(JNI_TRUE).to_bytes(4, byteorder="little"))
        else:
            mu.mem_write(is_static, int(JNI_FALSE).to_bytes(4, byteorder="little"))

        logger.debug(
            f"JNIEnv->ToReflectedMethod({pyclazz.jvm_name}, {method.name}, {is_static}) was called"
        )

        if method.name == "<init>" and method.signature.endswith("V"):
            obj = Constructor(pyclazz, method)
        else:
            obj = Method(pyclazz, method)

        return self.add_local_reference(jobject(obj))

    @native_method
    def get_superclass(self, mu, env, clazz_idx):
        jclazz = self.get_reference(clazz_idx)
        if not isinstance(jclazz, jclass):
            raise ValueError("Expected a jclass.")

        # Create class instance.
        class_obj = jclazz.value
        pyclass = class_obj.get_py_clazz()

        logger.debug(f"JNIEnv->GetSuperClass ({pyclass.jvm_name}) is called")

        pyclazz_super = pyclass.jvm_super
        if not pyclazz_super:
            raise RuntimeError(
                f"super class for {pyclass.jvm_name} is None!!! you should at least inherit Object!!!"
            )

        logger.debug(
            f"JNIEnv->GetSuperClass ({pyclass.jvm_name}) return ({pyclazz_super.jvm_name})"
        )
        clazz_super_object = self._class_loader.get_class_object(pyclazz_super)
        return self.add_local_reference(jclass(clazz_super_object))

    @native_method
    def is_assignable_from(self, mu, env, clazz_idx1, clazz_idx2):
        jclazz1 = self.get_reference(clazz_idx1)
        jclazz2 = self.get_reference(clazz_idx2)
        # Create class instance.
        class_obj1 = jclazz1.value
        pyclass1 = class_obj1.get_py_clazz()

        class_obj2 = jclazz2.value
        pyclass2 = class_obj2.get_py_clazz()

        logger.debug(
            f"JNIEnv->IsAssignableFrom ({pyclass1.jvm_name},{pyclass2.jvm_name}) is called"
        )
        r = JNI_FALSE
        jvm_super = pyclass1.jvm_super
        while jvm_super is not None:
            if jvm_super == pyclass2:
                r = JNI_TRUE
                break

            jvm_super = jvm_super.jvm_super

        logger.debug(
            f"JNIEnv->IsAssignableFrom ({pyclass1.jvm_name},{pyclass2.jvm_name}) return ({r})"
        )
        return r

    @native_method
    def to_reflected_field(self, mu, env, class_idx, field_id, is_static):
        """
        将源自 cls 的字段 ID 转换为 java.lang.reflect.Field 对象。
        """
        clazz = self.get_reference(class_idx)
        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value
        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field_by_id(field_id)
        if field is None:
            raise RuntimeError(
                f"Could not find field ('{field_id}') in class {pyclazz.jvm_name}."
            )

        from .classes.field import Field

        # We need to construct Field object. Field(pydeclaringClass, fieldName)
        field_obj = Field(pyclazz, field.name)

        return self.add_local_reference(jobject(field_obj))

    @native_method
    def throw(self, mu, env, obj):
        self._exception = obj
        return 0

    @native_method
    def throw_new(self, mu, env, clazz_idx, msg_ptr):
        msg = memory_helpers.read_utf8(mu, msg_ptr)
        logger.warning(f"JNIEnv->ThrowNew: {msg}")
        self._exception = 1  # Dummy, or class ref if possible
        return 0

    def _set_pending_exception(self, exception_type: str, message: str):
        """
        内部方法：设置一个待处理的异常。
        用于从其他 JNI 方法内部调用，避免通过 @native_method 装饰的方法出现参数解析问题。
        """
        logger.warning(f"JNIEnv pending exception: {exception_type}: {message}")
        self._exception = 1  # Dummy exception marker

    @native_method
    def exception_occurred(self, mu, env):
        if self._exception:
            if isinstance(self._exception, int):
                return self._exception
        return JAVA_NULL

    @native_method
    def exception_describe(self, mu, env):
        if self._exception:
            logger.warning("Exception is pending.")

    @native_method
    def exception_clear(self, mu, env):
        """
        清除当前抛出的任何异常。
        如果当前没有抛出异常，则此例程不起作用。
        """
        self._exception = None

    @native_method
    def fatal_error(self, mu, env, msg_ptr):
        msg = memory_helpers.read_utf8(mu, msg_ptr)
        logger.error(f"JNI Fatal Error: {msg}")
        sys.exit(1)

        return 0

    @native_method
    def push_local_frame(self, mu, env, capacity):
        """
        创建一个新的本地引用帧，在该帧中至少可以创建给定数量的本地引用。
        成功时返回 0，失败时返回负数并抛出 OutOfMemoryError。
        """
        logger.debug(f"JNIEnv->PushLocalFrame({capacity}) was called")
        self._local_frame_stack.append([])
        return 0

    @native_method
    def pop_local_frame(self, mu, env, result):
        """
        弹出当前的本地引用帧，释放其中包含的所有本地引用，
        并返回给定结果对象在紧前一个本地引用帧中的本地引用。
        """
        logger.debug(f"JNIEnv->PopLocalFrame({result}) was called")

        if not self._local_frame_stack:
            logger.warning("PopLocalFrame called with empty stack!")
            return result

        current_frame = self._local_frame_stack.pop()

        # Free all locals in this frame
        for idx in current_frame:
            if idx == result:
                # 需保留 result 对象。
                # 如果存在上一级帧，将其添加到上一级帧中，以延长其生命周期。
                # 这实际上使得 result 在上一级帧中变为有效的本地引用。
                if self._local_frame_stack:
                    self._local_frame_stack[-1].append(idx)
                    # 此时 idx 从当前帧逻辑上移除了（虽然后面代码是遍历，不修改 current_frame）
                    # 下面 continue 跳过 remove_by_id，从而保留引用。
                else:
                    # 如果没有上一级帧（即这是最顶层帧，虽然不常见），这里也被保留。
                    # 或者我们可以认为 PopLocalFrame 在顶层应该行为不同？
                    # 规范说: "The PopLocalFrame function returns a local reference to result in the previous local reference frame."
                    # 如果没有 previous frame，这就变成了 global scope 或者 error？
                    # 无论如何，保留它是安全的。
                    pass
                continue

            self._locals.remove_by_id(idx)

        return result

    @native_method
    def new_global_ref(self, mu, env, jobj):
        """
        创建一个对 obj 参数引用的对象的新全局引用。obj 参数可以是全局或本地引用。
        全局引用必须通过调用 DeleteGlobalRef() 显式释放。
        """
        logger.debug(f"JNIEnv->NewGlobalRef({jobj}) was called")

        if jobj == 0:
            return 0

        obj = self.get_reference(jobj)

        if obj is None:
            # If the reference is invalid, we might return NULL or throw.
            # JNI Spec says: "If obj refers to null, NewGlobalRef returns NULL."
            # But if obj itself is an invalid index, we probably should err.
            # Here we assume obj index 0 is invalid/NULL.
            return 0

        index = self.add_global_reference(obj)
        return index

    @native_method
    def delete_global_ref(self, mu, env, idx):
        """
        删除 globalRef 指向的全局引用。
        """
        logger.debug(f"JNIEnv->DeleteGlobalRef({idx}) was called")

        if idx == 0:
            return None

        obj = self.get_global_reference(idx)
        self.delete_global_reference(obj)

    @native_method
    def delete_local_ref(self, mu, env, idx):
        """
        删除 localRef 指向的本地引用。
        """
        logger.debug(f"JNIEnv->DeleteLocalRef({idx}) was called")

        if idx == 0:
            return None

        self.delete_local_reference(idx)

    @native_method
    def is_same_object(self, mu, env, ref1, ref2):
        """
        如果 ref1 和 ref2 引用相同的 Java 对象，或者是均 NULL，则返回 JNI_TRUE；否则，返回 JNI_FALSE。
        """
        logger.debug(f"JNIEnv->IsSameObject({ref1}, {ref2}) was called")

        if ref1 == 0 and ref2 == 0:
            return JNI_TRUE

        obj1 = self.get_reference(ref1)
        obj2 = self.get_reference(ref2)
        pyobj1 = self.jobject_to_pyobject(obj1)
        pyobj2 = self.jobject_to_pyobject(obj2)

        if pyobj1 is pyobj2:
            return JNI_TRUE

        return JNI_FALSE

    @native_method
    def new_local_ref(self, mu, env, ref):
        """
        创建一个引用与 ref 相同对象的新本地引用。
        给定的 ref 可以是全局引用或本地引用。如果 ref 引用 null，则返回 NULL。
        """
        logger.debug(f"JNIEnv->NewLocalRef({ref}) was called")

        obj = self.get_reference(ref)

        if obj is None:
            return 0

        return self.add_local_reference(obj)

    @native_method
    def ensure_local_capacity(self, mu, env, capacity):
        """
        确保当前本地引用帧中至少可以创建指定数量的本地引用。
        Returns 0 on success; otherwise returns a negative number to indicate an error.
        In this emulator, local refs are dynamic so we usually satisfy this.
        """
        return JNI_OK

    @native_method
    def exception_check(self, mu, env):
        # Returns JNI_TRUE if there is a pending exception, JNI_FALSE otherwise.
        return JNI_TRUE if self._exception else JNI_FALSE

    @native_method
    def alloc_object(self, mu, env, clazz_idx):
        """
        分配一个新的 Java 对象，而不调用该对象的任何构造函数。
        返回对新对象的引用，如果无法分配对象，则返回 NULL。
        """
        jclazz = self.get_reference(clazz_idx)
        if not isinstance(jclazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = jclazz.value
        pyclazz = class_obj.get_py_clazz()

        logger.debug(f"JNIEnv->AllocObject({pyclazz.jvm_name}) was called")

        # 在 Python 中，如果 __init__ 执行设置，则不调用 __init__ 进行实例化比较棘手。
        # 我们的对象通常在 __init__ 中设置。
        # Java AllocObject 分配内存但不运行构造函数。
        # 在 Python 中，我们可以创建实例而不调用 __init__ 吗？
        # 或者直接调用 pyclazz()（这会调用 __init__）？
        # 大多数模拟器实现只是调用 Python 构造函数。
        # 理想情况下，如果可能的话，我们应该拆分分配和初始化，但目前：
        obj = pyclazz()
        return self.add_local_reference(jobject(obj))

    def __new_object(self, mu, env, clazz_idx, method_id, args, args_type):
        # Get class reference.
        jclazz = self.get_reference(clazz_idx)
        if not isinstance(jclazz, jclass):
            raise ValueError("Expected a jclass.")

        # Create class instance.
        class_obj = jclazz.value

        pyclazz = class_obj.get_py_clazz()

        obj = pyclazz()

        # Get constructor method.
        method = pyclazz.find_method_by_id(method_id)
        if method.name != "<init>" or not method.signature.endswith("V"):
            raise ValueError(
                "Class constructor has the wrong name or does not return void."
            )

        logger.debug(
            f"JNIEnv->NewObjectX({pyclazz.jvm_name}, {method.name}, {args}) was called"
        )

        # Parse arguments.
        constructor_args = self.__read_args_common(
            mu, args, method.args_list, args_type
        )

        # Execute function.
        method.func(obj, self._emu, *constructor_args)

        return self.add_local_reference(jobject(obj))

    @native_method
    def new_object(
        self,
        mu,
        env,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
        arg7=0,
        arg8=0,
        arg9=0,
        arg10=0,
    ):
        return self.__new_object(
            mu,
            env,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10),
            0,
        )

    @native_method
    def new_object_v(self, mu, env, clazz_idx, method_id, args_v):
        return self.__new_object(mu, env, clazz_idx, method_id, args_v, 1)

    @native_method
    def new_object_a(self, mu, env, clazz_idx, method_id, args):
        return self.__new_object(mu, env, clazz_idx, method_id, args, 2)

    @native_method
    def get_object_class(self, mu, env, obj_idx):
        obj = self.get_reference(obj_idx)
        if obj is None:
            logger.error(f"get_object_class object id {obj_idx} is NULL or invalid.")
            return 0

        pyobj = JNIEnv.jobject_to_pyobject(obj)
        logger.debug(f"JNIEnv->GetObjectClass({pyobj}) was called")

        pyclazz = pyobj.__class__

        jvm_clazz = self._class_loader.get_class_object(pyclazz)
        return self.add_local_reference(jclass(jvm_clazz))

    @native_method
    def is_instance_of(self, mu, env, obj_idx, class_idx):
        """
        测试对象是否是类的实例。
        如果 obj 可以转换为 clazz，则返回 JNI_TRUE；否则，返回 JNI_FALSE。NULL 对象可以转换为任何类。
        """
        obj = self.get_reference(obj_idx)
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        clazz = self.get_reference(class_idx)
        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        # 转换检查
        # 我们需要检查 pyobj 是否是 pyclazz 的实例
        # 这涉及检查继承层次结构。
        # 如果涉及继承，简单的 ID 检查是不够的。

        # 检查 pyobj 类或其任何超类是否匹配 pyclazz。
        # 因为我们使用 jvm_id 来唯一标识类：
        class_obj = clazz.value
        pyclazz = class_obj.get_py_clazz()
        pyobj = JNIEnv.jobject_to_pyobject(obj)

        current_cls = pyobj.__class__
        while current_cls:
            if current_cls.jvm_id == pyclazz.jvm_id:
                return JNI_TRUE
            if hasattr(current_cls, "jvm_super") and current_cls.jvm_super:
                current_cls = current_cls.jvm_super
            else:
                break

        return JNI_FALSE

    @native_method
    def get_method_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        返回类或接口的实例（非静态）方法的方法 ID。
        该方法可以在 clazz 的超类之一中定义，并由 clazz 继承。
        该方法由其名称和签名确定。
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)
        logger.debug(
            "JNIEnv->GetMethodId(%d, %s, %s) was called" % (clazz_idx, name, sig)
        )

        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        pyclazz = class_obj.get_py_clazz()

        # logger.debug("get_method_id type %s" % (pyclazz))
        method = pyclazz.find_method(name, sig)

        if method is None:
            self._set_pending_exception("java/lang/NoSuchMethodError", f"{name} {sig}")
            return 0
        logger.debug(
            f"JNIEnv->GetMethodId({clazz_idx}, {name}, {sig}) return 0x{method.jvm_id:08X}"
        )
        return method.jvm_id

    def __call_xxx_method(
        self, mu, env, obj_idx, method_id, args, args_type, is_wide=False
    ):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")
        pyobj = JNIEnv.jobject_to_pyobject(obj)

        method = pyobj.__class__.find_method_by_id(method_id)
        if method is None:
            self._set_pending_exception("java/lang/NoSuchMethodError", str(method_id))
            return 0

        logger.debug(
            f"JNIEnv->CallXXXMethodX({pyobj.jvm_name}, {method.name} <{method.signature}>, {args}) was called"
        )

        # 解析参数。
        constructor_args = self.__read_args_common(
            mu, args, method.args_list, args_type
        )

        sig = method.signature
        name = method.name
        # 因为要支持多态,通过method_id找到的方法可能是基类的方法,不可以直接调用,需要获取签名和名字,通过子类的find_method才可以找到真正的实现方法.

        real_method = pyobj.__class__.find_method(name, sig)
        v = real_method.func(pyobj, self._emu, *constructor_args)

        if not is_wide:
            return v

        if self._emu.get_arch() == emu_const.ARCH_ARM64:
            return v

        if isinstance(v, float):
            import struct

            v = struct.unpack("<Q", struct.pack("<d", v))[0]

        rhigh = v >> 32
        rlow = v & 0xFFFFFFFF
        return (rlow, rhigh)

    @native_method
    def call_object_method(
        self,
        mu,
        env,
        obj_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        res = self.__call_xxx_method(
            mu,
            env,
            obj_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )
        return (
            self.add_local_reference(jobject(res))
            if res not in (None, JAVA_NULL)
            else JAVA_NULL
        )

    @native_method
    def call_object_method_v(self, mu, env, obj_idx, method_id, args):
        res = self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)
        return (
            self.add_local_reference(jobject(res))
            if res not in (None, JAVA_NULL)
            else JAVA_NULL
        )

    @native_method
    def call_object_method_a(self, mu, env, obj_idx, method_id, args):
        res = self.__call_xxx_method(mu, env, obj_idx, method_id, args, 2)
        return (
            self.add_local_reference(jobject(res))
            if res not in (None, JAVA_NULL)
            else JAVA_NULL
        )

    @native_method
    def call_boolean_method(
        self,
        mu,
        env,
        obj_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_xxx_method(
            mu,
            env,
            obj_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_boolean_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    @native_method
    def call_boolean_method_a(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    @native_method
    def call_byte_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_xxx_method(
            mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0
        )

    @native_method
    def call_byte_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    @native_method
    def call_byte_method_a(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    @native_method
    def call_char_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_xxx_method(
            mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0
        )

    @native_method
    def call_char_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    @native_method
    def call_char_method_a(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    @native_method
    def call_short_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_xxx_method(
            mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0
        )

    @native_method
    def call_short_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    @native_method
    def call_short_method_a(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    # 上层不知道参数个数，暂时多读几个寄存器，模拟器一般能处理多余参数
    # 如果参数超过6个，需要从栈读取，目前 __call_xxx_method 应该有处理或者 native_method 装饰器有处理
    @native_method
    def call_int_method(
        self,
        mu,
        env,
        obj_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_xxx_method(
            mu,
            env,
            obj_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_int_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    @native_method
    def call_int_method_a(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    @native_method
    def call_long_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self.__call_xxx_method(
            mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0, True
        )

    @native_method
    def call_long_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1, True)

    @native_method
    def call_long_method_a(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 2, True)

    @native_method
    def call_float_method(
        self,
        mu,
        env,
        obj_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_xxx_method(
            mu,
            env,
            obj_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_float_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    @native_method
    def call_float_method_a(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    @native_method
    def call_double_method(
        self,
        mu,
        env,
        obj_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_xxx_method(
            mu,
            env,
            obj_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
            True,
        )

    @native_method
    def call_double_method_v(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1, True)

    @native_method
    def call_double_method_a(self, mu, env, obj_idx, method_id, args):
        return self.__call_xxx_method(mu, env, obj_idx, method_id, args, 2, True)

    @native_method
    def call_void_method(
        self,
        mu,
        env,
        obj_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        self.__call_xxx_method(
            mu,
            env,
            obj_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_void_method_a(self, mu, env, obj_idx, method_id, args):
        self.__call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    @native_method
    def call_void_method_v(self, mu, env, obj_idx, method_id, args):
        self.__call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    def __call_nonvirtual_xxx_method(
        self, mu, env, obj_idx, clazz_idx, method_id, args, args_type, is_wide=False
    ):
        obj = self.get_reference(obj_idx)
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")
        pyobj = JNIEnv.jobject_to_pyobject(obj)

        clazz = self.get_reference(clazz_idx)
        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")
        class_obj = clazz.value
        pyclazz = class_obj.get_py_clazz()

        # 非虚调用：使用指定类(clazz)的方法，跳过 obj 的虚函数查找。
        method = pyclazz.find_method_by_id(method_id)
        if method is None:
            self._set_pending_exception("java/lang/NoSuchMethodError", str(method_id))
            return 0

        logger.debug(
            f"JNIEnv->CallNonvirtualXXXMethodX({pyobj.jvm_name}, {pyclazz.jvm_name}, {method.name}, {args}) was called"
        )

        constructor_args = self.__read_args_common(
            mu, args, method.args_list, args_type
        )

        v = method.func(pyobj, self._emu, *constructor_args)

        if not is_wide:
            return v

        if self._emu.get_arch() == emu_const.ARCH_ARM64:
            return v

        if isinstance(v, float):
            import struct

            v = struct.unpack("<Q", struct.pack("<d", v))[0]

        rhigh = v >> 32
        rlow = v & 0xFFFFFFFF
        return (rlow, rhigh)

    @native_method
    def call_nonvirtual_object_method(
        self,
        mu,
        env,
        obj_idx,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        res = self.__call_nonvirtual_xxx_method(
            mu,
            env,
            obj_idx,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )
        return (
            self.add_local_reference(jobject(res))
            if res not in (None, JAVA_NULL)
            else JAVA_NULL
        )

    @native_method
    def call_nonvirtual_object_method_v(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        res = self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 1
        )
        return (
            self.add_local_reference(jobject(res))
            if res not in (None, JAVA_NULL)
            else JAVA_NULL
        )

    @native_method
    def call_nonvirtual_object_method_a(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        res = self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 2
        )
        return (
            self.add_local_reference(jobject(res))
            if res not in (None, JAVA_NULL)
            else JAVA_NULL
        )

    @native_method
    def call_nonvirtual_boolean_method(
        self,
        mu,
        env,
        obj_idx,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_nonvirtual_xxx_method(
            mu,
            env,
            obj_idx,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_nonvirtual_boolean_method_v(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 1
        )

    @native_method
    def call_nonvirtual_boolean_method_a(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 2
        )

    @native_method
    def call_nonvirtual_byte_method(
        self,
        mu,
        env,
        obj_idx,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_nonvirtual_xxx_method(
            mu,
            env,
            obj_idx,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_nonvirtual_byte_method_v(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 1
        )

    @native_method
    def call_nonvirtual_byte_method_a(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 2
        )

    @native_method
    def call_nonvirtual_char_method(
        self,
        mu,
        env,
        obj_idx,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_nonvirtual_xxx_method(
            mu,
            env,
            obj_idx,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_nonvirtual_char_method_v(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 1
        )

    @native_method
    def call_nonvirtual_char_method_a(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 2
        )

    @native_method
    def call_nonvirtual_short_method(
        self,
        mu,
        env,
        obj_idx,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_nonvirtual_xxx_method(
            mu,
            env,
            obj_idx,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_nonvirtual_short_method_v(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 1
        )

    @native_method
    def call_nonvirtual_short_method_a(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 2
        )

    @native_method
    def call_nonvirtual_int_method(
        self,
        mu,
        env,
        obj_idx,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_nonvirtual_xxx_method(
            mu,
            env,
            obj_idx,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_nonvirtual_int_method_v(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 1
        )

    @native_method
    def call_nonvirtual_int_method_a(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 2
        )

    @native_method
    # call_nonvirtual_long_method
    def call_nonvirtual_long_method(
        self,
        mu,
        env,
        obj_idx,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_nonvirtual_xxx_method(
            mu,
            env,
            obj_idx,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
            True,
        )

    @native_method
    def call_nonvirtual_long_method_v(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 1, True
        )

    @native_method
    def call_nonvirtual_long_method_a(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 2, True
        )

    @native_method
    def call_nonvirtual_float_method(
        self,
        mu,
        env,
        obj_idx,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_nonvirtual_xxx_method(
            mu,
            env,
            obj_idx,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_nonvirtual_float_method_v(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 1
        )

    @native_method
    def call_nonvirtual_float_method_a(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 2
        )

    @native_method
    def call_nonvirtual_double_method(
        self,
        mu,
        env,
        obj_idx,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_nonvirtual_xxx_method(
            mu,
            env,
            obj_idx,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
            True,
        )

    @native_method
    def call_nonvirtual_double_method_v(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 1, True
        )

    @native_method
    def call_nonvirtual_double_method_a(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        return self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 2, True
        )

    @native_method
    def call_nonvirtual_void_method(
        self,
        mu,
        env,
        obj_idx,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        self.__call_nonvirtual_xxx_method(
            mu,
            env,
            obj_idx,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_nonvirtual_void_method_v(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 1
        )

    @native_method
    def call_nonvirtual_void_method_a(
        self, mu, env, obj_idx, clazz_idx, method_id, args
    ):
        self.__call_nonvirtual_xxx_method(
            mu, env, obj_idx, clazz_idx, method_id, args, 2
        )

    @native_method
    def get_field_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        返回类的实例（非静态）字段的字段 ID。该字段由其名称和签名指定。
        Get<type>Field 和 Set<type>Field 系列访问器函数使用字段 ID 来检索对象字段。
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)

        logger.debug(
            "JNIEnv->GetFieldId(%d, %s, %s) was called" % (clazz_idx, name, sig)
        )

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field(name, sig, False)

        if field is None:
            self._set_pending_exception("java/lang/NoSuchFieldError", f"{name} {sig}")
            return 0

        if field.ignore:
            return 0

        return field.jvm_id

    def __get_xxx_field(self, mu, env, obj_idx, field_id, is_wide=False):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        pyobj = JNIEnv.jobject_to_pyobject(obj)
        field = pyobj.__class__.find_field_by_id(field_id)

        if field is None:
            self.throw_new(mu, env, "java/lang/NoSuchFieldError", str(field_id))
            return 0

        logger.debug(
            "JNIEnv->GetXXXField(%s, %s <%s>) was called"
            % (pyobj.jvm_name, field.name, field.signature)
        )
        v = getattr(pyobj, field.name)
        if not is_wide:
            return v

        if self._emu.get_arch() == emu_const.ARCH_ARM64:
            return v

        if isinstance(v, float):
            import struct

            v = struct.unpack("<Q", struct.pack("<d", v))[0]

        rhigh = v >> 32
        rlow = v & 0xFFFFFFFF
        return (rlow, rhigh)

    @native_method
    def get_object_field(self, mu, env, obj_idx, field_id):
        res = self.__get_xxx_field(mu, env, obj_idx, field_id)
        if res is None:
            return JAVA_NULL
        return self.add_local_reference(jobject(res))

    @native_method
    def get_boolean_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id)

    @native_method
    def get_byte_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id)

    @native_method
    def get_char_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id)

    @native_method
    def get_short_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id)

    @native_method
    def get_int_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id)

    @native_method
    def get_long_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id, True)

    @native_method
    def get_float_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id)

    @native_method
    def get_double_field(self, mu, env, obj_idx, field_id):
        return self.__get_xxx_field(mu, env, obj_idx, field_id, True)

    def __set_xxx_field(self, mu, env, obj_idx, field_id, value, is_obj_value=False):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        pyobj = JNIEnv.jobject_to_pyobject(obj)
        field = pyobj.__class__.find_field_by_id(field_id)

        if field is None:
            self.throw_new(mu, env, "java/lang/NoSuchFieldError", str(field_id))
            # SetXXX 函数返回 void，所以直接返回
            return

        logger.debug(
            "JNIEnv->SetXXXField(%s, %s <%s>, %r) was called"
            % (pyobj.jvm_name, field.name, field.signature, value)
        )

        v = None
        if is_obj_value:
            value_idx = value
            value_obj = self.get_reference(value_idx)
            v = JNIEnv.jobject_to_pyobject(value_obj)

        else:
            v = value

        setattr(pyobj, field.name, v)

    @native_method
    def set_object_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value, True)

    @native_method
    def set_boolean_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)

    @native_method
    def set_byte_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)

    @native_method
    def set_char_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)

    @native_method
    def set_short_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)

    @native_method
    def set_int_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)

    @native_method
    def set_long_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)

    @native_method
    def set_float_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)

    @native_method
    def set_double_field(self, mu, env, obj_idx, field_id, value):
        self.__set_xxx_field(mu, env, obj_idx, field_id, value)

    @native_method
    def get_static_method_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        返回类的静态方法的方法 ID。该方法由其名称和签名指定。
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)
        logger.debug(
            "JNIEnv->GetStaticMethodId(%d, %s, %s) was called" % (clazz_idx, name, sig)
        )

        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()
        method = pyclazz.find_method(name, sig)

        if method is None:
            self._set_pending_exception("java/lang/NoSuchMethodError", f"{name} {sig}")
            return 0

        if method.ignore:
            return 0
        logger.debug(
            "JNIEnv->GetStaticMethodId(%d, %s, %s) return 0x%08X"
            % (clazz_idx, name, sig, method.jvm_id)
        )

        return method.jvm_id

    def __set_static_xxx_field(
        self, mu, env, clazz_idx, field_id, value, is_obj_value=False
    ):
        clazz = self.get_reference(clazz_idx)

        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value
        pyclazz = class_obj.get_py_clazz()
        field = pyclazz.find_field_by_id(field_id)

        if field is None:
            self.throw_new(mu, env, "java/lang/NoSuchFieldError", str(field_id))
            return

        v = None
        if is_obj_value:
            value_idx = value
            value_obj = self.get_reference(value_idx)
            v = JNIEnv.jobject_to_pyobject(value_obj)
        else:
            v = value

        logger.debug(
            f"JNIEnv->SetStaticXXXField({pyclazz.jvm_name}, {field.name}, {v}) was called"
        )
        field.static_value = v

    def __call_static_xxx_method(
        self, mu, env, clazz_idx, method_id, args, args_type, is_wide=False
    ):
        clazz = self.get_reference(clazz_idx)

        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        method = pyclazz.find_method_by_id(method_id)

        if method is None:
            self.throw_new(mu, env, "java/lang/NoSuchMethodError", str(method_id))
            return 0

        logger.debug(
            f"JNIEnv->CallStaticXXXMethodX({pyclazz.jvm_name}, {method.name} <{method.signature}>, 0x{args:08X}) was called"
        )

        # Parse arguments.
        constructor_args = self.__read_args_common(
            mu, args, method.args_list, args_type
        )

        v = method.func(self._emu, *constructor_args)
        if not is_wide:
            return v

        if self._emu.get_arch() == emu_const.ARCH_ARM64:
            return v

        if isinstance(v, float):
            import struct

            v = struct.unpack("<Q", struct.pack("<d", v))[0]

        rhigh = v >> 32
        rlow = v & 0xFFFFFFFF
        return (rlow, rhigh)

    @native_method
    def call_static_object_method(
        self,
        mu,
        env,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        res = self.__call_static_xxx_method(
            mu,
            env,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )
        return (
            self.add_local_reference(jobject(res))
            if res not in (None, JAVA_NULL)
            else JAVA_NULL
        )

    @native_method
    def call_static_object_method_v(self, mu, env, clazz_idx, method_id, args):
        res = self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)
        return (
            self.add_local_reference(jobject(res))
            if res not in (None, JAVA_NULL)
            else JAVA_NULL
        )

    @native_method
    def call_static_object_method_a(self, mu, env, clazz_idx, method_id, args):
        res = self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 2)
        return (
            self.add_local_reference(jobject(res))
            if res not in (None, JAVA_NULL)
            else JAVA_NULL
        )

    @native_method
    def call_static_boolean_method(
        self,
        mu,
        env,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_static_xxx_method(
            mu,
            env,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_static_boolean_method_v(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)

    @native_method
    def call_static_boolean_method_a(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 2)

    @native_method
    def call_static_byte_method(
        self,
        mu,
        env,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_static_xxx_method(
            mu,
            env,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_static_byte_method_v(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)

    @native_method
    def call_static_byte_method_a(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 2)

    @native_method
    def call_static_char_method(
        self,
        mu,
        env,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_static_xxx_method(
            mu,
            env,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_static_char_method_v(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)

    @native_method
    def call_static_char_method_a(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 2)

    @native_method
    def call_static_short_method(
        self,
        mu,
        env,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_static_xxx_method(
            mu,
            env,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_static_short_method_v(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)

    @native_method
    def call_static_short_method_a(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 2)

    @native_method
    def call_static_int_method(
        self,
        mu,
        env,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_static_xxx_method(
            mu,
            env,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_static_int_method_v(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)

    @native_method
    def call_static_int_method_a(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 2)

    @native_method
    def call_static_long_method(
        self,
        mu,
        env,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_static_xxx_method(
            mu,
            env,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
            True,
        )

    @native_method
    def call_static_long_method_v(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(
            mu, env, clazz_idx, method_id, args, 1, True
        )

    @native_method
    def call_static_long_method_a(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 2)

    @native_method
    def call_static_float_method(
        self,
        mu,
        env,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_static_xxx_method(
            mu,
            env,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_static_float_method_v(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)

    @native_method
    def call_static_float_method_a(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 2)

    @native_method
    def call_static_double_method(
        self,
        mu,
        env,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        return self.__call_static_xxx_method(
            mu,
            env,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
            True,
        )

    @native_method
    def call_static_double_method_v(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(
            mu, env, clazz_idx, method_id, args, 1, True
        )

    @native_method
    def call_static_double_method_a(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(
            mu, env, clazz_idx, method_id, args, 2, True
        )

    @native_method
    def call_static_void_method(
        self,
        mu,
        env,
        clazz_idx,
        method_id,
        arg1=0,
        arg2=0,
        arg3=0,
        arg4=0,
        arg5=0,
        arg6=0,
    ):
        self.__call_static_xxx_method(
            mu,
            env,
            clazz_idx,
            method_id,
            (arg1, arg2, arg3, arg4, arg5, arg6),
            0,
        )

    @native_method
    def call_static_void_method_v(self, mu, env, clazz_idx, method_id, args):
        self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)

    @native_method
    def call_static_void_method_a(self, mu, env, clazz_idx, method_id, args):
        return self.__call_static_xxx_method(mu, env, clazz_idx, method_id, args, 2)

    @native_method
    def get_static_field_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        返回类的静态字段的字段 ID。该字段由其名称和签名指定。
        GetStatic<type>Field 和 SetStatic<type>Field 系列访问器函数使用字段 ID 来检索静态字段。
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)

        logger.debug(
            "JNIEnv->GetStaticFieldId(%d, %s, %s) was called" % (clazz_idx, name, sig)
        )

        clazz = self.get_reference(clazz_idx)

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field(name, sig, True)

        if field is None:
            self.throw_new(mu, env, "java/lang/NoSuchFieldError", f"{name} {sig}")
            return 0

        if field.ignore:
            return 0

        return field.jvm_id

    def __get_static_xxx_field(self, mu, env, clazz_idx, field_id, is_wide=False):
        logger.debug(
            "JNIEnv->GetStaticXXXField(%d, %d) was called" % (clazz_idx, field_id)
        )

        clazz = self.get_reference(clazz_idx)

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field_by_id(field_id)

        r = field.static_value
        logger.debug("JNIEnv->GetStaticXXXField return %r" % r)
        v = field.static_value
        if not is_wide:
            return v

        if self._emu.get_arch() == emu_const.ARCH_ARM64:
            return v

        if isinstance(v, float):
            import struct

            v = struct.unpack("<Q", struct.pack("<d", v))[0]

        rhigh = v >> 32
        rlow = v & 0xFFFFFFFF
        return (rlow, rhigh)

    @native_method
    def get_static_object_field(self, mu, env, clazz_idx, field_id):
        res = self.__get_static_xxx_field(mu, env, clazz_idx, field_id)
        if res is None:
            return JAVA_NULL
        return self.add_local_reference(jobject(res))

    @native_method
    def get_static_boolean_field(self, mu, env, clazz_idx, field_id):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id)

    @native_method
    def get_static_byte_field(self, mu, env, clazz_idx, field_id):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id)

    @native_method
    def get_static_char_field(self, mu, env, clazz_idx, field_id):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id)

    @native_method
    def get_static_short_field(self, mu, env, clazz_idx, field_id):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id)

    @native_method
    def get_static_int_field(self, mu, env, clazz_idx, field_id):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id)

    @native_method
    def get_static_long_field(self, mu, env, clazz_idx, field_id):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id, True)

    @native_method
    def get_static_float_field(self, mu, env, clazz_idx, field_id):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id)

    @native_method
    def get_static_double_field(self, mu, env, clazz_idx, field_id):
        return self.__get_static_xxx_field(mu, env, clazz_idx, field_id, True)

    @native_method
    def set_static_object_field(self, mu, env, clazz_idx, field_id, value):
        self.__set_static_xxx_field(mu, env, clazz_idx, field_id, value, True)

    @native_method
    def set_static_boolean_field(self, mu, env, clazz_idx, field_id, value):
        self.__set_static_xxx_field(mu, env, clazz_idx, field_id, value)

    @native_method
    def set_static_byte_field(self, mu, env, clazz_idx, field_id, value):
        self.__set_static_xxx_field(mu, env, clazz_idx, field_id, value)

    @native_method
    def set_static_char_field(self, mu, env, clazz_idx, field_id, value):
        self.__set_static_xxx_field(mu, env, clazz_idx, field_id, value)

    @native_method
    def set_static_short_field(self, mu, env, clazz_idx, field_id, value):
        self.__set_static_xxx_field(mu, env, clazz_idx, field_id, value)

    @native_method
    def set_static_int_field(self, mu, env, clazz_idx, field_id, value):
        self.__set_static_xxx_field(mu, env, clazz_idx, field_id, value)

    @native_method
    def set_static_long_field(self, mu, env, clazz_idx, field_id, _, value_l, value_h):
        # 注意，由于刚好第四个参数是8个字节，arm32不会使用R3作为寄存器传递参数了，而是跳过R3直接使用栈，
        value = value_h << 32 | value_l
        logger.info(
            "JNIEnv->set_static_long_field (%u, %u, 0x%016X)"
            % (clazz_idx, field_id, value)
        )
        clazz = self.get_reference(clazz_idx)

        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field_by_id(field_id)
        field.static_value = value

    @native_method
    def set_static_float_field(self, mu, env, clazz_idx, field_id, value):
        import struct

        val = struct.unpack("<f", value.to_bytes(4, "little"))[0]
        self.__set_static_xxx_field(mu, env, clazz_idx, field_id, val)

    @native_method
    def set_static_double_field(
        self, mu, env, clazz_idx, field_id, _, value_l, value_h
    ):
        # 暂时假设 ARM32 拆分约定，如处理 long 一样
        value = value_h << 32 | value_l
        import struct

        val = struct.unpack("<d", value.to_bytes(8, "little"))[0]
        self.__set_static_xxx_field(mu, env, clazz_idx, field_id, val)

    @native_method
    def new_string(self, mu, env, unicode_ptr, length):
        try:
            b = mu.mem_read(unicode_ptr, length * 2)
            pystr = b.decode("utf-16-le")
            string = String(pystr)
            return self.add_local_reference(jobject(string))
        except Exception as e:
            logger.error(f"new_string failed: {e}")
            return 0

    @native_method
    def get_string_length(self, mu, env, string):
        str_ref = self.get_reference(string)
        if str_ref is None or str_ref.value is JAVA_NULL:
            return 0
        return len(str_ref.value.get_py_string())

    @native_method
    def get_string_chars(self, mu, env, string, is_copy_ptr):
        str_ref = self.get_reference(string)
        if str_ref is None or str_ref.value is JAVA_NULL:
            return 0

        pystr = str_ref.value.get_py_string()
        data = pystr.encode("utf-16-le")
        # 为字符串字符分配内存
        total_size = len(data) + 2
        buf = self._emu.memory.map(0, 4 + total_size, UC_PROT_READ | UC_PROT_WRITE)
        mu.mem_write(buf, total_size.to_bytes(4, "little"))

        ptr = buf + 4
        mu.mem_write(ptr, data)
        mu.mem_write(ptr + len(data), b"\x00\x00")

        if is_copy_ptr != 0:
            mu.mem_write(is_copy_ptr, int(JNI_TRUE).to_bytes(4, "little"))

        return ptr

    @native_method
    def release_string_chars(self, mu, env, string, chars_ptr):
        if chars_ptr == 0:
            return
        true_buf = chars_ptr - 4
        sz = int.from_bytes(mu.mem_read(true_buf, 4), "little")
        logger.debug(f"ReleaseStringChars unmap size {sz}")
        self._emu.memory.unmap(true_buf, sz + 4)

    @native_method
    def new_string_utf(self, mu, env, utf8_ptr):
        pystr = memory_helpers.read_utf8(mu, utf8_ptr)
        logger.debug("JNIEnv->NewStringUtf(%s) was called" % pystr)
        string = String(pystr)
        idx = self.add_local_reference(jobject(string))
        logger.debug("JNIEnv->NewStringUtf(%s) return id(%d)" % (pystr, idx))
        return idx

    @native_method
    def get_string_utf_length(self, mu, env, string):
        str_ref = self.get_reference(string)
        str_obj = str_ref.value
        if str_obj == JAVA_NULL:
            return 0

        str_val = str_obj.get_py_string()
        return len(str_val)

    @native_method
    def get_string_utf_chars(self, mu, env, string, is_copy_ptr):
        logger.debug(f"GetStringUtfChars({string}, {is_copy_ptr}) was called")

        str_ref = self.get_reference(string)
        if isinstance(str_ref.value, String):
            str_obj = str_ref.value
            if str_obj == JAVA_NULL:
                return JAVA_NULL

            str_val = str_obj.get_py_string()
        else:
            str_val = str_ref.value

        # 使用模拟器内存映射来模拟 malloc
        total_size = len(str_val) + 1  # +1 for null terminator if implied by logic?
        # 原始代码使用了 len(str_val) + 1。
        # utf-8 编码的长度可能与 python 计算的长度不同？
        # memory_helpers.write_utf8 写入字符串 + 空终止符。

        data = str_val.encode("utf-8")
        total_size = len(data) + 1

        buf = self._emu.memory.map(0, 4 + total_size, UC_PROT_READ | UC_PROT_WRITE)
        mu.mem_write(buf, total_size.to_bytes(4, "little"))
        str_ptr = buf + 4

        logger.debug("=> %s" % str_val)
        if is_copy_ptr != 0:
            # 如果进行了复制，则 isCopy 设置为 JNI_TRUE；如果没有进行复制，则设置为 JNI_FALSE。
            # 我们分配新内存并复制字符串数据，所以返回 JNI_TRUE。
            mu.mem_write(is_copy_ptr, int(JNI_TRUE).to_bytes(1, byteorder="little"))

        memory_helpers.write_utf8(mu, str_ptr, str_val)

        return str_ptr

    @native_method
    def release_string_utf_chars(self, mu, env, string, utf8_ptr):
        if utf8_ptr == 0:
            return
        true_buf = utf8_ptr - 4
        sz = int.from_bytes(mu.mem_read(true_buf, 4), "little")
        logger.debug(f"ReleaseStringUtfChars unmap size {sz}")
        self._emu.memory.unmap(true_buf, sz + 4)

    @native_method
    def get_array_length(self, mu, env, array_idx):
        arr_ref = self.get_reference(array_idx)
        if arr_ref is None or arr_ref.value is JAVA_NULL:
            return 0
        pyobj = JNIEnv.jobject_to_pyobject(arr_ref)
        # Array 包装了一个 list 或 bytearray
        if isinstance(pyobj, Array):
            return len(pyobj.get_py_items())  # 假设 Array 有 get_py_items 或类似 list
        return len(pyobj)  # 回退

    @native_method
    def new_object_array(self, mu, env, size, class_idx, obj_init):
        logger.debug(
            "JNIEnv->NewObjectArray(%d, %u, %r) was called"
            % (size, class_idx, obj_init)
        )
        clazz = self.get_reference(class_idx)

        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        arr_item_cls_name = pyclazz.jvm_name

        pyarr = []
        for i in range(0, size):
            pyarr.append(JAVA_NULL)

        if obj_init != JAVA_NULL:
            obj = self.get_reference(obj_init)
            pyobj = self.jobject_to_pyobject(obj)
            pyarr[0] = pyobj

        new_jvm_name = ""
        # '[' 前缀在 JNI/JVM 描述符中标识数组类。
        if arr_item_cls_name[0] == "[":
            new_jvm_name = "[%s" % arr_item_cls_name
        else:
            new_jvm_name = "[L%s;" % arr_item_cls_name

        pyarray_clazz = self._class_loader.find_class_by_name(new_jvm_name)
        if pyarray_clazz is None:
            # jvm_name=None, jvm_fields=None, jvm_ignore=False, jvm_super=None
            # 动态创建 Array 新类？目前抛出异常。
            self.throw_new(mu, env, "java/lang/NoClassDefFoundError", new_jvm_name)
            return 0

        arr = pyarray_clazz(pyarr)
        return self.add_local_reference(jobject(arr))

    @native_method
    def get_object_array_element(self, mu, env, array_idx, item_idx):
        logger.debug(
            "JNIEnv->GetObjectArrayElement(%u, %u) was called" % (array_idx, item_idx)
        )

        array_obj = self.get_reference(array_idx)

        array_pyobj = JNIEnv.jobject_to_pyobject(array_obj)
        pyobj_item = array_pyobj[item_idx]
        if pyobj_item == JAVA_NULL:
            return JAVA_NULL
        return self.add_local_reference(jobject(pyobj_item))

    @native_method
    def set_object_array_element(self, mu, env, array_idx, index, obj_idx):
        logger.debug(
            "JNIEnv->SetObjectArrayElement(%u, %u, %u) was called"
            % (array_idx, index, obj_idx)
        )
        array_obj = self.get_reference(array_idx)

        array_pyobj = JNIEnv.jobject_to_pyobject(array_obj)
        obj = self.get_reference(obj_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        array_pyobj[index] = pyobj

    @native_method
    def new_boolean_array(self, mu, env, length):
        arr = Array([0] * length)
        return self.add_local_reference(jobject(arr))

    @native_method
    def new_byte_array(self, mu, env, bytelen):
        logger.debug("JNIEnv->NewByteArray(%u) was called" % bytelen)
        barr = bytearray([0] * bytelen)
        arr = Array(barr)
        return self.add_local_reference(jobject(arr))

    @native_method
    def new_char_array(self, mu, env, length):
        arr = Array([0] * length)
        return self.add_local_reference(jobject(arr))

    @native_method
    def new_short_array(self, mu, env, length):
        arr = Array([0] * length)
        return self.add_local_reference(jobject(arr))

    @native_method
    def new_int_array(self, mu, env, length):
        logger.debug("JNIEnv->NewIntArray(%u) was called" % length)
        arr = Array([0] * length)
        return self.add_local_reference(jobject(arr))

    @native_method
    def new_long_array(self, mu, env, length):
        arr = Array([0] * length)
        return self.add_local_reference(jobject(arr))

    @native_method
    def new_float_array(self, mu, env, length):
        arr = Array([0.0] * length)
        return self.add_local_reference(jobject(arr))

    @native_method
    def new_double_array(self, mu, env, length):
        arr = Array([0.0] * length)
        return self.add_local_reference(jobject(arr))

    @native_method
    def get_boolean_array_elements(self, mu, env, array_idx, is_copy_ptr):
        return self._get_primitive_array_elements(mu, env, array_idx, is_copy_ptr, 1)

    def _get_primitive_array_elements(self, mu, env, array_idx, is_copy_ptr, item_size):
        if is_copy_ptr != 0:
            mu.mem_write(is_copy_ptr, int(JNI_TRUE).to_bytes(4, "little"))

        obj = self.get_reference(array_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        items = pyobj.get_py_items()  # 返回 list 或 bytearray
        items_len = len(items)
        extra_n = 4  # 在开头存储长度（协议）

        buf = self._emu.memory.map(
            0, extra_n + items_len * item_size, UC_PROT_READ | UC_PROT_WRITE
        )

        # 写入长度（以字节为单位）以支持通用释放
        total_size = items_len * item_size
        mu.mem_write(buf, total_size.to_bytes(extra_n, "little"))

        # 写数据
        # 如果是 bytearray，很简单
        if item_size == 1 and isinstance(items, (bytes, bytearray)):
            mu.mem_write(buf + extra_n, items)
        else:
            # 用于其他类型的 struct pack
            import struct

            # 目前简单的手动写入是为了避免复杂的 fmt 构造
            # 可优化
            ptr = buf + extra_n
            for item in items:
                # 处理可能的 float/int 不匹配或只是强制 int？
                # JNI 需要原始字节。Python 类型比较宽松。
                # 目前除了 float/double 外假设为 int
                val = item
                if isinstance(val, float) and item_size == 4:
                    val_bytes = struct.pack("<f", val)
                elif isinstance(val, float) and item_size == 8:
                    val_bytes = struct.pack("<d", val)
                else:
                    val_bytes = int(val).to_bytes(item_size, "little", signed=(val < 0))

                mu.mem_write(ptr, val_bytes)
                ptr += item_size

        return buf + extra_n

    @native_method
    def get_byte_array_elements(self, mu, env, array_idx, is_copy_ptr):
        return self._get_primitive_array_elements(mu, env, array_idx, is_copy_ptr, 1)

    @native_method
    def get_char_array_elements(self, mu, env, array_idx, is_copy_ptr):
        return self._get_primitive_array_elements(mu, env, array_idx, is_copy_ptr, 2)

    @native_method
    def get_short_array_elements(self, mu, env, array_idx, is_copy_ptr):
        return self._get_primitive_array_elements(mu, env, array_idx, is_copy_ptr, 2)

    @native_method
    def get_int_array_elements(self, mu, env, array_idx, is_copy_ptr):
        return self._get_primitive_array_elements(mu, env, array_idx, is_copy_ptr, 4)

    @native_method
    def get_long_array_elements(self, mu, env, array_idx, is_copy_ptr):
        return self._get_primitive_array_elements(mu, env, array_idx, is_copy_ptr, 8)

    def _release_primitive_array_elements(self, mu, env, array_idx, elems, mode):
        if elems == JAVA_NULL:
            return
        logger.debug(
            f"JNIEnv->ReleasePrimitiveArrayElements({array_idx}, {elems}, {mode}) was called"
        )

        # extra_n used during allocation (4 bytes for size)
        extra_n = 4
        true_buf = elems - extra_n

        # Read total size (bytes)
        b = mu.mem_read(true_buf, 4)
        sz = int.from_bytes(b, byteorder="little", signed=False)

        # Copu back logic
        # 0: copy back and free
        # 1 (JNI_COMMIT): copy back, do not free
        # 2 (JNI_ABORT): free without copy back

        if mode != 2:  # JNI_ABORT
            ref = self.get_reference(array_idx)
            obj = ref

            # Unwrap jobject/jarray wrapper if present
            # Note: imported jobject above from .jni_ref
            if isinstance(obj, jobject):
                obj = obj.value

            data_bytes = mu.mem_read(elems, sz)

            if isinstance(obj, ByteArray):
                # ByteArray implementation (androidemu/java/classes/array.py) uses private member __pyitems
                # which is mangled to _Array__pyitems
                if hasattr(obj, "_Array__pyitems"):
                    obj._Array__pyitems = list(data_bytes)
                else:
                    logger.warning("ByteArray does not have _Array__pyitems attribute.")
            else:
                # Helper to determine item size based on object type or try to use existing length
                # If we don't know the type, we might fail to update correctly for IntArray/LongArray.
                # Let's iterate based on existing list length
                current_len = len(obj) if hasattr(obj, "__len__") else 0
                if current_len > 0:
                    item_size = sz // current_len
                    import struct

                    fmt = ""
                    if item_size == 1:
                        # Likely boolean or byte (if not caught by ByteArray check above)
                        fmt = "b"  # signed char
                    elif item_size == 2:
                        fmt = "h"  # short
                    elif item_size == 4:
                        fmt = "i"  # int (or float?) - simple int for now
                        if (
                            hasattr(obj, "jvm_name")
                            and "Float" in obj.__class__.__name__
                        ):
                            fmt = "f"
                    elif item_size == 8:
                        fmt = "q"  # long (or double?)
                        if (
                            hasattr(obj, "jvm_name")
                            and "Double" in obj.__class__.__name__
                        ):
                            fmt = "d"

                    if fmt:
                        # unpack
                        new_values = []
                        # struct.iter_unpack is available in Python 3.4+
                        try:
                            # Handling endianness
                            fmt = "<" + fmt
                            for i in range(current_len):
                                chunk = data_bytes[i * item_size : (i + 1) * item_size]
                                val = struct.unpack(fmt, chunk)[0]
                                new_values.append(val)

                            # Update directly if possible
                            if hasattr(obj, "_Array__pyitems"):
                                obj._Array__pyitems = new_values
                            else:
                                # Fallback (might fail if no setter)
                                for i in range(current_len):
                                    obj[i] = new_values[i]
                        except Exception as e:
                            logger.warning(
                                f"Failed to unpack or set array data in Release: {e}"
                            )

        if mode != 1:  # Not JNI_COMMIT
            self._emu.memory.unmap(true_buf, sz + 4)

    @native_method
    def get_float_array_elements(self, mu, env, array_idx, is_copy_ptr):
        return self._get_primitive_array_elements(mu, env, array_idx, is_copy_ptr, 4)

    @native_method
    def get_double_array_elements(self, mu, env, array_idx, is_copy_ptr):
        return self._get_primitive_array_elements(mu, env, array_idx, is_copy_ptr, 8)

    @native_method
    def release_boolean_array_elements(self, mu, env, array_idx, elems, mode):
        self._release_primitive_array_elements(mu, env, array_idx, elems, mode)

    @native_method
    def release_byte_array_elements(self, mu, env, array_idx, elems, mode):
        self._release_primitive_array_elements(mu, env, array_idx, elems, mode)

    @native_method
    def release_char_array_elements(self, mu, env, array_idx, elems, mode):
        self._release_primitive_array_elements(mu, env, array_idx, elems, mode)

    @native_method
    def release_short_array_elements(self, mu, env, array_idx, elems, mode):
        self._release_primitive_array_elements(mu, env, array_idx, elems, mode)

    @native_method
    def release_int_array_elements(self, mu, env, array_idx, elems, mode):
        self._release_primitive_array_elements(mu, env, array_idx, elems, mode)

    @native_method
    def release_long_array_elements(self, mu, env, array_idx, elems, mode):
        self._release_primitive_array_elements(mu, env, array_idx, elems, mode)

    @native_method
    def release_float_array_elements(self, mu, env, array_idx, elems, mode):
        self._release_primitive_array_elements(mu, env, array_idx, elems, mode)

    @native_method
    def release_double_array_elements(self, mu, env, array_idx, elems, mode):
        self._release_primitive_array_elements(mu, env, array_idx, elems, mode)

    @native_method
    def get_boolean_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        logger.debug(
            "JNIEnv->GetBooleanArrayRegion(%u, %u, %u, 0x%x) was called"
            % (array_idx, start, len_in, buf_ptr)
        )
        obj = self.get_reference(array_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        items = pyobj.get_py_items()
        # 布尔值是 1 字节
        mu.mem_write(buf_ptr, bytes(items[start : start + len_in]))
        return None

    @native_method
    def get_byte_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        logger.debug(
            "JNIEnv->GetByteArrayRegion(%u, %u, %u, 0x%x) was called"
            % (array_idx, start, len_in, buf_ptr)
        )

        if buf_ptr == 0:
            logger.error("JNIEnv->GetByteArrayRegion called with NULL buf_ptr!")
            return

        obj = self.get_reference(array_idx)
        """
        if not isinstance(obj, jbyteArray):
            raise ValueError('Expected a jbyteArray.')
        """
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        barr = pyobj.get_py_items()
        try:
            mu.mem_write(buf_ptr, bytes(barr[start : start + len_in]))
        except Exception as e:
            logger.error(f"GetByteArrayRegion mem_write failed at 0x{buf_ptr:x}: {e}")
            raise

        return None

    @native_method
    def get_char_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        logger.debug(
            "JNIEnv->GetCharArrayRegion(%u, %u, %u, 0x%x) was called"
            % (array_idx, start, len_in, buf_ptr)
        )
        obj = self.get_reference(array_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        items = pyobj.get_py_items()
        import struct

        packed_bytes = b"".join(
            struct.pack("<H", item) for item in items[start : start + len_in]
        )
        mu.mem_write(buf_ptr, packed_bytes)
        return None

    @native_method
    def get_short_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        logger.debug(
            "JNIEnv->GetShortArrayRegion(%u, %u, %u, 0x%x) was called"
            % (array_idx, start, len_in, buf_ptr)
        )
        obj = self.get_reference(array_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        items = pyobj.get_py_items()
        import struct

        packed_bytes = b"".join(
            struct.pack("<h", item) for item in items[start : start + len_in]
        )
        mu.mem_write(buf_ptr, packed_bytes)
        return None

    @native_method
    def get_int_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        logger.debug(
            "JNIEnv->GetIntArrayRegion(%u, %u, %u, 0x%x) was called"
            % (array_idx, start, len_in, buf_ptr)
        )
        obj = self.get_reference(array_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        items = pyobj.get_py_items()
        import struct

        packed_bytes = b"".join(
            struct.pack("<i", item) for item in items[start : start + len_in]
        )
        mu.mem_write(buf_ptr, packed_bytes)
        return None

    @native_method
    def get_long_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        logger.debug(
            "JNIEnv->GetLongArrayRegion(%u, %u, %u, 0x%x) was called"
            % (array_idx, start, len_in, buf_ptr)
        )
        obj = self.get_reference(array_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        items = pyobj.get_py_items()
        import struct

        packed_bytes = b"".join(
            struct.pack("<q", item) for item in items[start : start + len_in]
        )
        mu.mem_write(buf_ptr, packed_bytes)
        return None

    @native_method
    def get_float_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        logger.debug(
            "JNIEnv->GetFloatArrayRegion(%u, %u, %u, 0x%x) was called"
            % (array_idx, start, len_in, buf_ptr)
        )
        obj = self.get_reference(array_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        items = pyobj.get_py_items()
        import struct

        packed_bytes = b"".join(
            struct.pack("<f", item) for item in items[start : start + len_in]
        )
        mu.mem_write(buf_ptr, packed_bytes)
        return None

    @native_method
    def get_double_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        logger.debug(
            "JNIEnv->GetDoubleArrayRegion(%u, %u, %u, 0x%x) was called"
            % (array_idx, start, len_in, buf_ptr)
        )
        obj = self.get_reference(array_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        items = pyobj.get_py_items()
        import struct

        packed_bytes = b"".join(
            struct.pack("<d", item) for item in items[start : start + len_in]
        )
        mu.mem_write(buf_ptr, packed_bytes)
        return None

    @native_method
    def set_boolean_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        logger.debug(
            "JNIEnv->SetBooleanArrayRegion(%u, %u, %u, 0x%x) was called"
            % (array_idx, start, len_in, buf_ptr)
        )
        obj = self.get_reference(array_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        items = pyobj.get_py_items()
        # 布尔值是 1 字节
        data = mu.mem_read(buf_ptr, len_in)
        for i in range(len_in):
            items[start + i] = data[i] != 0
        return None

    @native_method
    def set_byte_array_region(self, mu, env, arrayJREF, startIndex, length, bufAddress):
        string = memory_helpers.read_byte_array(mu, bufAddress, length)
        logger.debug("JNIEnv->SetByteArrayRegion was called")
        arr = Array(string)
        self.set_local_reference(arrayJREF, jobject(arr))

    @native_method
    def set_char_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        self._set_primitive_array_region(
            mu, env, array_idx, start, len_in, buf_ptr, 2, "<H"
        )

    @native_method
    def set_short_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        self._set_primitive_array_region(
            mu, env, array_idx, start, len_in, buf_ptr, 2, "<h"
        )

    @native_method
    def set_int_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        self._set_primitive_array_region(
            mu, env, array_idx, start, len_in, buf_ptr, 4, "<i"
        )

    @native_method
    def set_long_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        self._set_primitive_array_region(
            mu, env, array_idx, start, len_in, buf_ptr, 8, "<q"
        )

    @native_method
    def set_float_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        self._set_primitive_array_region(
            mu, env, array_idx, start, len_in, buf_ptr, 4, "<f"
        )

    @native_method
    def set_double_array_region(self, mu, env, array_idx, start, len_in, buf_ptr):
        self._set_primitive_array_region(
            mu, env, array_idx, start, len_in, buf_ptr, 8, "<d"
        )

    def _set_primitive_array_region(
        self, mu, env, array_idx, start, len_in, buf_ptr, item_size, fmt
    ):
        logger.debug(
            f"JNIEnv->SetPrimitiveArrayRegion({array_idx}) item_size={item_size}"
        )
        obj = self.get_reference(array_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        items = pyobj.get_py_items()

        data = mu.mem_read(buf_ptr, len_in * item_size)
        import struct

        # 我们需要解包数据并更新项目
        # 高效解包
        unpacked = struct.unpack(fmt * len_in, data)
        for i in range(len_in):
            items[start + i] = unpacked[i]

    @native_method
    def register_natives(self, mu, env, clazz_id, methods, methods_count):
        logger.debug(
            "JNIEnv->RegisterNatives(%d, 0x%08X, %d) was called"
            % (clazz_id, methods, methods_count)
        )

        clazz = self.get_reference(clazz_id)

        if not isinstance(clazz, jclass):
            raise ValueError(
                "Expected a jclass but type %r value %r getted." % (type(clazz), clazz)
            )

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()
        ptr_sz = self._emu.get_ptr_size()

        for i in range(0, methods_count):
            ptr_name = memory_helpers.read_ptr_sz(
                mu, (i * 3 * ptr_sz) + methods, ptr_sz
            )
            ptr_sign = memory_helpers.read_ptr_sz(
                mu, (i * 3 * ptr_sz) + methods + ptr_sz, ptr_sz
            )
            ptr_func = memory_helpers.read_ptr_sz(
                mu, (i * 3 * ptr_sz) + methods + 2 * ptr_sz, ptr_sz
            )

            name = memory_helpers.read_utf8(mu, ptr_name)
            signature = memory_helpers.read_utf8(mu, ptr_sign)

            pyclazz.register_native(name, signature, ptr_func)

        return JNI_OK

    @native_method
    def unregister_natives(self, mu, env, clazz_id):
        logger.debug(f"JNIEnv->UnregisterNatives({clazz_id}) (Stub) was called")
        return JNI_OK

    @native_method
    def monitor_enter(self, mu, env, obj):
        logger.debug(f"JNIEnv->MonitorEnter({obj}) was called")
        # 存根：成功的 monitor 获取
        return JNI_OK

    @native_method
    def monitor_exit(self, mu, env, obj):
        logger.debug(f"JNIEnv->MonitorExit({obj}) was called")
        # 存根：成功的 monitor 释放
        return JNI_OK

    @native_method
    def get_java_vm(self, mu, env, vm):
        logger.debug("JNIEnv->GetJavaVM(0x%08x) was called" % vm)

        mu.mem_write(vm, self._emu.java_vm.address_ptr.to_bytes(4, byteorder="little"))

        return JNI_OK

    @native_method
    def get_string_region(self, mu, env, string, start, length, buf_ptr):
        # 将从偏移量 start 开始的 len 个 Unicode 字符复制到给定的缓冲区 buf
        str_ref = self.get_reference(string)
        if str_ref is None or str_ref.value is JAVA_NULL:
            return None

        pystr = str_ref.value.get_py_string()
        substr = pystr[start : start + length]
        data = substr.encode("utf-16-le")
        mu.mem_write(buf_ptr, data)
        return None

    @native_method
    def get_string_utf_region(self, mu, env, string, start, length, buf_ptr):
        # 将从偏移量 start 开始的 len 个 Unicode 字符转换为修改后的 UTF-8 编码
        # 并将结果放入给定的缓冲区 buf 中。
        str_ref = self.get_reference(string)
        if str_ref is None or str_ref.value is JAVA_NULL:
            return None

        pystr = str_ref.value.get_py_string()
        # JNI GetStringUTFRegion 长度是以字符为单位，而不是字节。
        substr = pystr[start : start + length]

        # 修改后的 UTF-8 略有不同，但对于标准 ascii/常用字符，它与 utf-8 匹配。
        # 这里暂时实现标准 utf-8。
        data = substr.encode(
            "utf-8"
        )  # + b'\0' ? 规范说“将结果放入”，没有明确说明如果它填满缓冲区是否需要空终止符。
        # 但通常 GetStringUTFRegion 用于固定缓冲区。
        # "标准的 GetStringUTFChars 返回以 null 结尾的"
        # "GetStringUTFRegion ... 将结果放入给定的缓冲区".
        mu.mem_write(buf_ptr, data)
        return None

    @native_method
    def get_primitive_array_critical(self, mu, env, array_idx, is_copy_ptr):
        # 语义：行为类似于 Get<Type>ArrayElements 但有限制。
        # 我们可以将其实现为 GetByteArrayElements 通用回退或类似的。
        # 由于我们在不检查对象的情况下无法轻易知道类型，
        # 我们可以检查对象类型。
        obj = self.get_reference(array_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        # 检查是否为 Array
        if not isinstance(pyobj, Array):
            return 0

        # 我们把它当作字节来进行原始访问？或者通用的？
        # 实际上它返回 void*。
        # 如果我们假设 byte/bool，我们可以只使用 size=1 的 _get_primitive_array_elements
        # 但如果是 IntArray，我们需要 size=4。
        # PyArray 存储项目。
        # 让我们试着从数组内容或签名推断大小。
        # Array 类通常不会在这个模拟器中显式存储类型，只是 python 列表。
        # 但 NewIntArray 创建 Array([0]*len)。

        # 回退：如果可能的话，只返回指向数据的指针。
        # 我们将重用带有大小检测的 _get_primitive_array_elements？
        # 安全回退：视为字节数组（大小 1），但这可能会破坏格式，如果我们写回整数？
        # 仅当我们写回时。

        # 让我们假设通常用于图像的“关键”通用访问的字节数组。
        return self._get_primitive_array_elements(mu, env, array_idx, is_copy_ptr, 1)

    @native_method
    def release_primitive_array_critical(self, mu, env, array_idx, carray, mode):
        # 释放。如果我们支持模式（提交等），我们会这样做。
        pass

    @native_method
    def get_string_critical(self, mu, env, string, is_copy_ptr):
        return self.get_string_chars(mu, env, string, is_copy_ptr)

    @native_method
    def release_string_critical(self, mu, env, string, carray):
        self.release_string_chars(mu, env, string, carray)

    @native_method
    def new_weak_global_ref(self, mu, env, obj):
        return self.new_global_ref(mu, env, obj)

    @native_method
    def delete_weak_global_ref(self, mu, env, obj):
        return self.delete_global_ref(mu, env, obj)

    @native_method
    def new_direct_byte_buffer(self, mu, env, address, capacity):
        logger.debug(f"NewDirectByteBuffer(0x{address:x}, {capacity})")
        if address == 0:
            return JAVA_NULL
        return self.add_local_reference(jobject(DirectByteBuffer(address, capacity)))

    @native_method
    def get_direct_buffer_address(self, mu, env, buf):
        # buf 是一个 jobject (引用)
        obj_ref = self.get_reference(buf)
        if obj_ref is None or obj_ref.value is JAVA_NULL:
            return 0

        obj = obj_ref.value
        # 假设它是 Buffer 或 ByteBuffer 或子类
        # 我们需要访问它的地址字段。
        # 由于我们使用 Python 对象，我们可以检查属性。
        if hasattr(obj, "_address"):
            return obj._address

        logger.warning(
            f"GetDirectBufferAddress called on object {obj} which has no _address"
        )
        return 0

    @native_method
    def get_direct_buffer_capacity(self, mu, env, buf):
        obj_ref = self.get_reference(buf)
        if obj_ref is None or obj_ref.value is JAVA_NULL:
            return -1

        obj = obj_ref.value
        if hasattr(obj, "_capacity"):
            return obj._capacity

        logger.warning(
            f"GetDirectBufferCapacity called on object {obj} which has no _capacity"
        )
        return -1

    @native_method
    def get_object_ref_type(self, mu, env, obj):
        # 0=JNIInvalidRefType, 1=JNILocalRefType, 2=JNIGlobalRefType, 3=JNIWeakGlobalRefType
        # 我们可以从范围推断。
        if obj == 0:
            return 0
        if self._locals.in_range(obj):
            return 1  # JNILocalRefType
        elif self._globals.in_range(obj):
            return 2  # JNIGlobalRefType

        return 0  # JNIInvalidRefType
