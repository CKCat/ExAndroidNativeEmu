from ..java_class_def import JavaClassDef
from ..java_field_def import JavaFieldDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String
from .array import ByteArray
import base64


class Base64(
    Object, metaclass=JavaClassDef, jvm_name="android/util/Base64", jvm_super=Object
):
    def __init__(self):
        Object.__init__(self)

    # Constants
    DEFAULT = 0
    NO_PADDING = 1
    NO_WRAP = 2
    CRL_LF = 4
    URL_SAFE = 8

    # We define fields too if native code accesses them
    DEFAULT_F = JavaFieldDef("DEFAULT", "I", True, DEFAULT)
    NO_PADDING_F = JavaFieldDef("NO_PADDING", "I", True, NO_PADDING)
    NO_WRAP_F = JavaFieldDef("NO_WRAP", "I", True, NO_WRAP)
    URL_SAFE_F = JavaFieldDef("URL_SAFE", "I", True, URL_SAFE)

    @staticmethod
    @java_method_def(
        name="encodeToString",
        args_list=["[B", "I"],
        signature="([BI)Ljava/lang/String;",
        native=False,
    )
    def encodeToString(emu, data_arr, flags):
        # data_arr is ByteArray
        data = bytes(data_arr)
        # flags handling is complex (CRLF, wrap etc), but for emu, standard b64 usually works unless strict.
        # Python base64.b64encode adds padding.
        # android NO_PADDING removes it.
        # URL_SAFE uses -_ instead of +/

        if flags & Base64.URL_SAFE:
            encoded = base64.urlsafe_b64encode(data).decode("ascii")
        else:
            encoded = base64.b64encode(data).decode("ascii")

        if flags & Base64.NO_WRAP:
            # Python b64encode doesn't wrap by default (unlike MIME), so this is fine.
            pass

        if flags & Base64.NO_PADDING:
            encoded = encoded.rstrip("=")

        return String(encoded)

    @staticmethod
    @java_method_def(
        name="decode",
        args_list=["jstring", "I"],
        signature="(Ljava/lang/String;I)[B",
        native=False,
    )
    def decode(emu, str_obj, flags):
        s = str_obj.get_py_string()
        if flags & Base64.URL_SAFE:
            # Correct padding if missing
            missing_padding = len(s) % 4
            if missing_padding:
                s += "=" * (4 - missing_padding)
            decoded = base64.urlsafe_b64decode(s)
        else:
            missing_padding = len(s) % 4
            if missing_padding:
                s += "=" * (4 - missing_padding)
            decoded = base64.b64decode(s)

        return ByteArray(decoded)
