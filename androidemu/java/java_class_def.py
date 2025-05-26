import inspect

from loguru import logger

from .jvm_id_conter import next_cls_id

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
        self.class_object = None
        logger.debug(
            f"Register class {self.__name__} with jvm_name {self.jvm_name} and jvm_id {self.jvm_id}"
        )
        # 注册所有已定义的 Java 方法。
        for func in inspect.getmembers(self, predicate=inspect.isfunction):
            # func[0] 是函数名，func[1] 是函数对象
            if hasattr(func[1], "jvm_method"):
                method = func[1].jvm_method
                self.jvm_methods[method.jvm_id] = method

        # 注册所有已定义的 Java 字段。
        if jvm_fields is not None:
            for jvm_field in jvm_fields:
                self.jvm_fields[jvm_field.jvm_id] = jvm_field
        logger.debug(f"Registered {len(self.jvm_methods)} methods.")
        logger.debug(f"Registered {len(self.jvm_fields)} fields.")
        super().__init__(name, base, ns)

    def __new__(self, name: str, base: tuple, ns: dict, **kargs):
        return super().__new__(self, name, base, ns)

    def register_native(self, name: str, signature: str, ptr_func: int):
        found = False
        found_method = None

        # 查找已定义的 jvm 方法。
        for method in self.jvm_methods.values():
            if method.name == name and method.signature == signature:
                method.native_addr = ptr_func
                found = True
                found_method = method
                break

        if not found:
            logger.warning(
                f"Register native ({name}, {signature}, 0x{ptr_func:08X}) failed on class { self.__name__}."
            )
            return
            # raise RuntimeError("Register native ('%s', '%s') failed on class %s." % (name, signature, cls.__name__))
        logger.debug(
            f"Registered native function ({name}, {signature}, 0x{ptr_func:08X}) to {self.__name__}.{found_method.func_name}"
        )

    def find_method(self, name: str, signature: str):
        for method in self.jvm_methods.values():
            if method.name == name and method.signature == signature:
                return method
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
        assert (
            signature_no_ret[0] == "(" and signature_no_ret[-1] == ")"
        ), "signature_no_ret error"
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
        for field in cls.jvm_fields.values():
            if (
                field.name == name
                and field.signature == signature
                and field.is_static == is_static
            ):
                return field

        if cls.jvm_super is not None:
            return cls.jvm_super.find_field(name, signature, is_static)

        return None

    def find_field_by_id(cls, jvm_id):
        if jvm_id in cls.jvm_fields:
            return cls.jvm_fields[jvm_id]
        if cls.jvm_super is not None:
            return cls.jvm_super.find_field_by_id(jvm_id)

        return None
