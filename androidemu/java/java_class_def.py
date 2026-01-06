import inspect

from loguru import logger

from .jvm_id_counter import next_cls_id
from .java_field_def import JavaFieldDef

# Class 函数实现基本原则：

# 1.所有 python 函数(包括 __init__ )传入传出参数能用 python 基本类型表示的，一律用 python 类型表示，例如字符串用 pystring，整数为用 1

# 2.所有模拟的 java 函数（ java_method_def 修饰的函数）除八个基本类型外， 传入传出都是 java 类型，例如字符串用 String，整数用 Integer，
# 注意区分 Integer 和 Int，Integer 是对象不属于八个基本类型。

# 基本数据类型--四类八种：整数类（byte、short、int、long）、浮点类（float、double）、字符类（char）、布尔型（boolean）；

# 3.需要看函数返回值签名分析，如果是八个基本类型，用 python 整数代表 java 整数，用 python float 代表 java double 和 float。


class JavaClassDef(type):
    def __init__(
        self,
        name: str,
        base: tuple,
        ns: dict,
        jvm_name: str = None,
        jvm_fields: list = None,
        jvm_ignore: bool = False,
        jvm_super: str = None,
    ):
        self.jvm_id: int = next_cls_id()
        self.jvm_name: str = jvm_name
        self.jvm_methods: dict = dict()
        self.jvm_fields: dict = dict()
        self.jvm_ignore: bool = jvm_ignore
        self.jvm_super: str = jvm_super

        # Speed up lookup
        self.jvm_methods_idx: dict = dict()
        self.jvm_fields_idx: dict = dict()
        logger.debug(
            f"Register class {self.__name__} with jvm_name {self.jvm_name} and jvm_id {self.jvm_id}"
        )
        # 注册所有已定义的 Java 方法。
        for func in inspect.getmembers(self, predicate=inspect.isfunction):
            # func[0] 是函数名，func[1] 是函数对象
            if hasattr(func[1], "jvm_method"):
                method = func[1].jvm_method
                self.jvm_methods[method.jvm_id] = method
                self.jvm_methods_idx[(method.name, method.signature)] = method

        # 扫描 define 的 JavaFieldDef
        for name, value in inspect.getmembers(self):
            if isinstance(value, JavaFieldDef):
                self.jvm_fields[value.jvm_id] = value
                self.jvm_fields_idx[(value.name, value.signature, value.is_static)] = (
                    value
                )

        # 注册所有已定义的 Java 字段。
        if jvm_fields is not None:
            for jvm_field in jvm_fields:
                self.jvm_fields[jvm_field.jvm_id] = jvm_field
                self.jvm_fields_idx[
                    (jvm_field.name, jvm_field.signature, jvm_field.is_static)
                ] = jvm_field
        logger.debug(f"Registered {len(self.jvm_methods)} methods.")
        logger.debug(f"Registered {len(self.jvm_fields)} fields.")
        super().__init__(name, base, ns)

    def __new__(self, name: str, base: tuple, ns: dict, **kargs):
        return super().__new__(self, name, base, ns)

    def register_native(self, name: str, signature: str, ptr_func: int):
        key = (name, signature)
        if key in self.jvm_methods_idx:
            method = self.jvm_methods_idx[key]
            method.native_addr = ptr_func
            logger.debug(
                f"Registered native function ({name}, {signature}, 0x{ptr_func:08X}) to {self.__name__}.{method.func_name}"
            )
            return

        # Dynamically add the native method if it doesn't exist
        from .java_method_def import JavaMethodDef

        # Generate a dummy function name
        func_name = f"{name}_{ptr_func:x}"
        new_method = JavaMethodDef(
            func_name, name, signature, True, args_list=None, modifier=0
        )
        new_method.native_addr = ptr_func

        self.jvm_methods[new_method.jvm_id] = new_method
        self.jvm_methods_idx[key] = new_method

        logger.info(
            f"Dynamically registered native function ({name}, {signature}, 0x{ptr_func:08X}) to {self.__name__}."
        )

    def find_method(self, name: str, signature: str):
        key = (name, signature)
        if key in self.jvm_methods_idx:
            return self.jvm_methods_idx[key]
        if self.jvm_super is not None:
            return self.jvm_super.find_method(name, signature)

        return None

    def find_method_sig_with_no_ret(self, name: str, signature_no_ret: str):
        """用于支持 java 反射， java 反射签名都没有返回值。


        Args:
            name (str): 方法名
            signature_no_ret (str): java 反射签名, 没有返回值。类似 (ILjava/lang/String;)。

        Returns:
            _type_: _description_
        """
        assert signature_no_ret[0] == "(" and signature_no_ret[-1] == ")", (
            "signature_no_ret error"
        )
        for method in self.jvm_methods.values():
            if method.name == name and method.signature.startswith(signature_no_ret):
                return method

        if self.jvm_super is not None:
            return self.jvm_super.find_method_sig_with_no_ret(name, signature_no_ret)
        return None

    def find_method_by_id(cls, jvm_id: int):
        if jvm_id in cls.jvm_methods:
            return cls.jvm_methods[jvm_id]
        if cls.jvm_super is not None:
            return cls.jvm_super.find_method_by_id(jvm_id)

        return None

    def find_field(cls, name, signature, is_static):
        key = (name, signature, is_static)
        if key in cls.jvm_fields_idx:
            return cls.jvm_fields_idx[key]

        if cls.jvm_super is not None:
            return cls.jvm_super.find_field(name, signature, is_static)

        return None

    def find_field_by_id(cls, jvm_id):
        if jvm_id in cls.jvm_fields:
            return cls.jvm_fields[jvm_id]
        if cls.jvm_super is not None:
            return cls.jvm_super.find_field_by_id(jvm_id)

        return None
