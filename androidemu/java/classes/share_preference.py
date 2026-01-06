import xml.dom.minidom

from ...utils import misc_utils
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .string import String


class Editor(
    metaclass=JavaClassDef, jvm_name="android/content/SharedPreferences$Editor"
):
    def __init__(self, sp_impl):
        self.__sp = sp_impl
        self.__changes = {}
        self.__cleared = False

    @java_method_def(
        name="putString",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
        native=False,
    )
    def putString(self, emu, key, value):
        self.__changes[key.get_py_string()] = value.get_py_string()
        return self

    @java_method_def(
        name="putInt",
        args_list=["jstring", "jint"],
        signature="(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;",
        native=False,
    )
    def putInt(self, emu, key, value):
        self.__changes[key.get_py_string()] = value
        return self

    @java_method_def(
        name="putBoolean",
        args_list=["jstring", "jboolean"],
        signature="(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;",
        native=False,
    )
    def putBoolean(self, emu, key, value):
        self.__changes[key.get_py_string()] = value
        return self

    @java_method_def(
        name="putLong",
        args_list=["jstring", "jlong"],
        signature="(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;",
        native=False,
    )
    def putLong(self, emu, key, value):
        self.__changes[key.get_py_string()] = value
        return self

    @java_method_def(
        name="putFloat",
        args_list=["jstring", "jfloat"],
        signature="(Ljava/lang/String;F)Landroid/content/SharedPreferences$Editor;",
        native=False,
    )
    def putFloat(self, emu, key, value):
        self.__changes[key.get_py_string()] = value
        return self

    @java_method_def(
        name="clear",
        signature="()Landroid/content/SharedPreferences$Editor;",
        native=False,
    )
    def clear(self, emu):
        self.__cleared = True
        return self

    @java_method_def(
        name="remove",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
        native=False,
    )
    def remove(self, emu, key):
        self.__changes[key.get_py_string()] = None  # Signal removal
        return self

    @java_method_def(name="commit", signature="()Z", native=False)
    def commit(self, emu):
        self.__sp._apply_changes(self.__changes, self.__cleared)
        self.__changes = {}
        self.__cleared = False
        return True

    @java_method_def(name="apply", signature="()V", native=False)
    def apply(self, emu):
        self.commit(emu)


class SharedPreferences(
    metaclass=JavaClassDef, jvm_name="android/content/SharedPreferences"
):
    def __init__(self, emu, path):
        vfs_root = emu.get_vfs_root()
        self.__path = misc_utils.vfs_path_to_system_path(
            vfs_root, path
        )  # Store real path
        self.__values = {}

        try:
            dom = xml.dom.minidom.parse(self.__path)
            root = dom.documentElement

            # Helper to parse tags
            def parse_nodes(tag_name, converter):
                nodes = root.getElementsByTagName(tag_name)
                for node in nodes:
                    if node.hasAttribute("name"):
                        k = node.getAttribute("name")
                        try:
                            v = (
                                converter(node.getAttribute("value"))
                                if tag_name != "string"
                                else (
                                    node.childNodes[0].data if node.childNodes else ""
                                )
                            )
                            self.__values[k] = v
                        except Exception:
                            pass

            parse_nodes("string", str)
            parse_nodes("int", int)
            parse_nodes("long", int)
            parse_nodes("boolean", lambda x: x.lower() == "true")
            parse_nodes("float", float)

        except Exception:
            # File might not exist or be empty, which is fine
            # Ensure directory exists for future writes if possible,
            # but usually assuming app data dir structure exists or we let write fail/create on fly?
            # We don't create dirs here, assuming filesystem structure is managed elsewhere or we rely on python open() in _save
            pass

    def _save(self):
        try:
            doc = xml.dom.minidom.Document()
            map_node = doc.createElement("map")
            doc.appendChild(map_node)

            for k, v in self.__values.items():
                if isinstance(v, bool):
                    node = doc.createElement("boolean")
                    node.setAttribute("name", k)
                    node.setAttribute("value", "true" if v else "false")
                    map_node.appendChild(node)
                elif isinstance(v, int):
                    # Heuristic: if fits in 32-bit signed, use int, else long
                    if -2147483648 <= v <= 2147483647:
                        node = doc.createElement("int")
                    else:
                        node = doc.createElement("long")
                    node.setAttribute("name", k)
                    node.setAttribute("value", str(v))
                    map_node.appendChild(node)
                elif isinstance(v, float):
                    node = doc.createElement("float")
                    node.setAttribute("name", k)
                    node.setAttribute("value", str(v))
                    map_node.appendChild(node)
                elif isinstance(v, str):
                    node = doc.createElement("string")
                    node.setAttribute("name", k)
                    # Use text node for string content
                    if v:
                        node.appendChild(doc.createTextNode(v))
                    map_node.appendChild(node)

            # Ensure directory exists
            import os

            os.makedirs(os.path.dirname(self.__path), exist_ok=True)

            with open(self.__path, "w", encoding="utf-8") as f:
                f.write(doc.toxml())
        except Exception as e:
            from loguru import logger

            logger.error(f"Failed to save SharedPreferences to {self.__path}: {e}")

    def _apply_changes(self, changes, cleared):
        if cleared:
            self.__values.clear()

        for k, v in changes.items():
            if v is None:
                if k in self.__values:
                    del self.__values[k]
            else:
                self.__values[k] = v

        self._save()

    @java_method_def(
        name="edit",
        signature="()Landroid/content/SharedPreferences$Editor;",
        native=False,
    )
    def edit(self, emu):
        return Editor(self)

    @java_method_def(
        name="getString",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        native=False,
    )
    def getString(self, emu, skey, sdefault):
        pyKey = skey.get_py_string()
        val = self.__values.get(pyKey)
        if val is not None:
            return String(str(val))
        return sdefault

    @java_method_def(
        name="getInt",
        args_list=["jstring", "jint"],
        signature="(Ljava/lang/String;I)I",
        native=False,
    )
    def getInt(self, emu, skey, idefault):
        pyKey = skey.get_py_string()
        return self.__values.get(pyKey, idefault)

    @java_method_def(
        name="getBoolean",
        args_list=["jstring", "jboolean"],
        signature="(Ljava/lang/String;Z)Z",
        native=False,
    )
    def getBoolean(self, emu, skey, bdefault):
        pyKey = skey.get_py_string()
        return self.__values.get(pyKey, bdefault)

    @java_method_def(
        name="getLong",
        args_list=["jstring", "jlong"],
        signature="(Ljava/lang/String;J)J",
        native=False,
    )
    def getLong(self, emu, skey, ldefault):
        pyKey = skey.get_py_string()
        return self.__values.get(pyKey, ldefault)

    @java_method_def(
        name="getFloat",
        args_list=["jstring", "jfloat"],
        signature="(Ljava/lang/String;F)F",
        native=False,
    )
    def getFloat(self, emu, skey, fdefault):
        pyKey = skey.get_py_string()
        return self.__values.get(pyKey, fdefault)
