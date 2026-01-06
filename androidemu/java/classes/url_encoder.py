from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String
import urllib.parse


class URLEncoder(
    Object, metaclass=JavaClassDef, jvm_name="java/net/URLEncoder", jvm_super=Object
):
    def __init__(self):
        Object.__init__(self)

    @staticmethod
    @java_method_def(
        name="encode",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        native=False,
    )
    def encode(emu, s, enc):
        if not s:
            return String(None)

        py_s = s.get_py_string()
        # py_enc = enc.get_py_string() # Ignored mostly in python as quote handles it standardly, but could verify charset

        # java URLEncoder encodes space as +
        encoded = urllib.parse.quote_plus(py_s)
        return String(encoded)
