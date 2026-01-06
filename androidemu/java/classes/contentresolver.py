from loguru import logger

from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .bundle import Bundle


class ContentResolver(
    metaclass=JavaClassDef, jvm_name="android/content/ContentResolver"
):
    def __init__(self):
        pass

    @java_method_def(
        name="getType",
        args_list=["jobject"],
        signature="(Landroid/net/Uri;)Ljava/lang/String;",
        native=False,
    )
    def getType(self, emu, uri):
        logger.debug(f"getType {uri.get_py_string()}")
        return None

    @java_method_def(
        name="call",
        args_list=["jobject", "jstring", "jstring", "jobject"],
        signature="(Landroid/net/Uri;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;",
        native=False,
    )
    def call(self, emu, uri, method, arg, extras):
        logger.debug(f"call {uri} {method} {arg} {extras}")
        pyuri_str = uri.get_py_string()
        py_method = method.get_py_string()
        py_arg = arg.get_py_string()
        if pyuri_str == "content://settings/system":
            if py_method == "GET_system" and py_arg == "__MTA_DEVICE_INFO__":
                return Bundle()

        elif pyuri_str == "content://settings/secure":
            if py_method == "GET_secure":
                if py_arg == "android_id":
                    # aid from config (default to a known value if missing)
                    aid = emu.config.get("android_id", "39cc04a2ae83db0b")
                    m = {"value": aid}
                    return Bundle(m)

                elif py_arg == "accessibility_enabled":
                    return Bundle()

        logger.warning(
            f"ContentResolver.call {pyuri_str} {py_method} {py_arg} not implemented"
        )
        return None

    @java_method_def(
        name="query",
        args_list=[
            "jobject",
            "[Ljava/lang/String;",
            "jstring",
            "[Ljava/lang/String;",
            "jstring",
        ],
        signature="(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;",
        native=False,
    )
    def query(self, emu, uri, projection, selection, selectionArgs, sortOrder):
        uri_str = uri.get_py_string()
        logger.debug(f"ContentResolver.query {uri_str}")
        return None
