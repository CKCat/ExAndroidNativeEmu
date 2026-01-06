from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String


class Locale(
    Object, metaclass=JavaClassDef, jvm_name="java/util/Locale", jvm_super=Object
):
    def __init__(self, language="en", country=""):
        Object.__init__(self)
        self.__language = language
        self.__country = country
        self.__variant = ""

    @java_method_def(
        name="<init>",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def ctor_lang(self, emu, language):
        self.__language = language.get_py_string()
        self.__country = ""
        self.__variant = ""

    @java_method_def(
        name="<init>",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)V",
        native=False,
    )
    def ctor_lang_country(self, emu, language, country):
        self.__language = language.get_py_string()
        self.__country = country.get_py_string()
        self.__variant = ""

    @java_method_def(
        name="<init>",
        args_list=["jstring", "jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        native=False,
    )
    def ctor_full(self, emu, language, country, variant):
        self.__language = language.get_py_string()
        self.__country = country.get_py_string()
        self.__variant = variant.get_py_string()

    @java_method_def(name="getLanguage", signature="()Ljava/lang/String;", native=False)
    def getLanguage(self, emu):
        return String(self.__language)

    @java_method_def(name="getCountry", signature="()Ljava/lang/String;", native=False)
    def getCountry(self, emu):
        return String(self.__country)

    @java_method_def(name="getVariant", signature="()Ljava/lang/String;", native=False)
    def getVariant(self, emu):
        return String(self.__variant)

    @java_method_def(name="toString", signature="()Ljava/lang/String;", native=False)
    def toString(self, emu):
        # language + "_" + country + "_" + variant, but handle empty parts
        parts = [self.__language]
        if self.__country:
            parts.append(self.__country)
            if self.__variant:
                parts.append(self.__variant)
        return String("_".join(parts))

    @staticmethod
    @java_method_def(name="getDefault", signature="()Ljava/util/Locale;", native=False)
    def getDefault(emu):
        # Return US as default for now
        return Locale("en", "US")

    @staticmethod
    @java_method_def(
        name="setDefault",
        args_list=["java/util/Locale"],
        signature="(Ljava/util/Locale;)V",
        native=False,
    )
    def setDefault(emu, locale):
        # No-op or store globally if needed
        pass
