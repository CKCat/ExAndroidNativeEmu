from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .string import String
from .byte_array_input_stream import ByteArrayInputStream


class URLConnection(
    Object, metaclass=JavaClassDef, jvm_name="java/net/URLConnection", jvm_super=Object
):
    def __init__(self, url):
        Object.__init__(self)
        self.__url = url
        self.__doInput = True
        self.__doOutput = False

    @java_method_def(name="connect", signature="()V", native=False)
    def connect(self, emu):
        pass

    @java_method_def(
        name="getInputStream", signature="()Ljava/io/InputStream;", native=False
    )
    def getInputStream(self, emu):
        # Return empty stream or dummy content
        # For emulation, maybe we want to actually fetch? Or just return empty for safety.
        # Returning empty ByteArrayInputStream
        return ByteArrayInputStream(bytearray())

    @java_method_def(
        name="getOutputStream", signature="()Ljava/io/OutputStream;", native=False
    )
    def getOutputStream(self, emu):
        from .byte_array_output_stream import ByteArrayOutputStream

        return ByteArrayOutputStream()

    @java_method_def(
        name="setRequestProperty",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)V",
        native=False,
    )
    def setRequestProperty(self, emu, key, value):
        pass

    @java_method_def(
        name="setDoInput", args_list=["jboolean"], signature="(Z)V", native=False
    )
    def setDoInput(self, emu, doinput):
        self.__doInput = doinput

    @java_method_def(
        name="setDoOutput", args_list=["jboolean"], signature="(Z)V", native=False
    )
    def setDoOutput(self, emu, dooutput):
        self.__doOutput = dooutput
