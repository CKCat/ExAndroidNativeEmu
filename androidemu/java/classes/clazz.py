import io

from loguru import logger

from ...const.java_const import JAVA_NULL
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def

from .field import Field
from .method import Method
from .string import String


class Class(metaclass=JavaClassDef, jvm_name="java/lang/Class"):
    _basic_types = ["Z", "B", "C", "D", "F", "I", "J", "S"]

    def __init__(self, pyclazz, class_loader):
        self.class_loader = class_loader
        self.__pyclazz = pyclazz
        self.__descriptor_represent = pyclazz.jvm_name

    @java_method_def(
        name="getClassLoader",
        signature="()Ljava/lang/ClassLoader;",
        native=False,
    )
    def getClassLoader(self, emu):
        return self.class_loader

    @staticmethod
    @java_method_def(
        name="forName",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/Class;",
        native=False,
    )
    def forName(emu, name):
        clz_name = name.get_py_string().replace(".", "/")
        clazz_def = emu.java_classloader.find_class_by_name(clz_name)

        if clazz_def is None:
            raise RuntimeError("Class.forName failed for %s" % clz_name)

        return emu.java_classloader.get_class_object(clazz_def)

    @java_method_def(
        name="getSuperclass", signature="()Ljava/lang/Class;", native=False
    )
    def getSuperclass(self, emu):
        if not self.__pyclazz.jvm_super:
            return JAVA_NULL
        # Assuming jvm_super is also a registered class we can find?
        # In current design, jvm_super is a python class reference.
        # We need its Class object.
        jvm_super = self.__pyclazz.jvm_super
        # Often jvm_super in JavaClassDef is the python class itself.
        # Check if the loader has the class object for it
        if jvm_super:
            obj = self.class_loader.get_class_object(jvm_super)
            if obj:
                return obj

        # If it's a type/class not fully initialized or not found:
        return JAVA_NULL

    @java_method_def(
        name="getMethod",
        args_list=["jstring", "jobject"],
        signature="(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
        native=False,
    )
    def getMethod(self, emu, name, parameterTypes):
        # 1. Try current class (and public check in theory, but ignoring permissions for now)
        try:
            return self.getDeclaredMethod(emu, name, parameterTypes)
        except Exception:
            pass

        # 2. Try super class if exists
        super_cls = self.getSuperclass(emu)
        if super_cls and super_cls != JAVA_NULL:
            return super_cls.getMethod(emu, name, parameterTypes)

        raise RuntimeError(
            f"Method {name.get_py_string()} not found in class {self.getName(emu).get_py_string()}"
        )

    @java_method_def(name="getName", signature="()Ljava/lang/String;", native=False)
    def getName(self, emu):
        name = self.__descriptor_represent
        assert name is not None

        name = name.replace("/", ".")
        return String(name)

    @java_method_def(
        name="getCanonicalName", signature="()Ljava/lang/String;", native=False
    )
    def getCanonicalName(self, emu):
        name = self.getName(emu).get_py_string()

        if name[0] == "[":
            dims = 0
            for ch in name:
                if ch == "[":
                    dims += 1

                else:
                    break

            # 去除[
            name = name[dims:]
            if name[0] == "L":
                # 去除类型前的L
                name = name[1:]

            for i in range(dims):
                name = name + "[]"

        # $->.
        name = name.replace("$", ".")
        return String(name)

    def get_jni_descriptor(self):
        return self.__descriptor_represent

    def get_py_clazz(self):
        return self.__pyclazz

    @java_method_def(
        name="getDeclaredField",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/reflect/Field;",
        native=False,
    )
    def getDeclaredField(self, emu, name):
        logger.debug("getDeclaredField %s" % name)
        reflected_field = Field(self.__pyclazz, name.get_py_string())
        return reflected_field

    @java_method_def(
        name="getDeclaredMethod",
        args_list=["jstring", "jobject"],
        signature="(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
        native=False,
    )
    def getDeclaredMethod(self, emu, name, parameterTypes):
        logger.debug(
            "getDeclaredMethod name:[%r] parameterTypes:[%r]" % (name, parameterTypes)
        )
        sbuf = io.StringIO()
        sbuf.write("(")
        for item in parameterTypes:
            desc = item.get_jni_descriptor()
            if desc[0] == "[" or desc in Class._basic_types:
                sbuf.write(desc)
            #
            else:
                sbuf.write("L")
                sbuf.write(desc)
                sbuf.write(";")

        sbuf.write(")")

        signature_no_ret = sbuf.getvalue()
        pyname = name.get_py_string()
        pymethod = self.__pyclazz.find_method_sig_with_no_ret(pyname, signature_no_ret)
        if pymethod is None:
            raise RuntimeError(
                f"Method {pyname} with signature {signature_no_ret} not found in {self.__descriptor_represent}"
            )

        reflected_method = Method(self.__pyclazz, pymethod)
        logger.debug("getDeclaredMethod return %r" % reflected_method)
        return reflected_method

    def __repr__(self):
        return "Class(%s)" % self.__descriptor_represent
