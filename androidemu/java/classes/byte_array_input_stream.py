from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .stream import InputStream


class ByteArrayInputStream(
    InputStream,
    metaclass=JavaClassDef,
    jvm_name="java/io/ByteArrayInputStream",
    jvm_super=InputStream,
):
    def __init__(self, data):
        InputStream.__init__(self, data=data)

    @java_method_def(name="<init>", args_list=["[B"], signature="([B)V", native=False)
    def ctor(self, emu, data):
        # data is ByteArray wrapper or list
        if hasattr(data, "get_py_items"):
            self._InputStream__data = data.get_py_items()
        else:
            self._InputStream__data = data
        self._InputStream__pos = 0
