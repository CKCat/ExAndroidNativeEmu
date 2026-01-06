from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .array import ByteArray
from loguru import logger


class Cipher(
    Object, metaclass=JavaClassDef, jvm_name="javax/crypto/Cipher", jvm_super=Object
):
    ENCRYPT_MODE = 1
    DECRYPT_MODE = 2

    def __init__(self, transformation):
        Object.__init__(self)
        self.__transformation = transformation
        self.__cipher_algo = None
        self.__mode = None
        self.__key = None
        self.__iv = None
        self.__opmode = 0
        self.__padding = "PKCS5Padding"  # Default assumption
        self._parse_transformation(transformation)

    def _parse_transformation(self, trans):
        # e.g. AES/CBC/PKCS5Padding
        parts = trans.split("/")
        self.__algo_name = parts[0].upper()
        if len(parts) > 1:
            self.__mode_name = parts[1].upper()
        else:
            self.__mode_name = "ECB"  # Default?

        if len(parts) > 2:
            self.__padding = parts[2]

    @staticmethod
    @java_method_def(
        name="getInstance",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljavax/crypto/Cipher;",
        native=False,
    )
    def getInstance(emu, transformation):
        return Cipher(transformation.get_py_string())

    @java_method_def(
        name="init",
        args_list=["jint", "java/security/Key"],
        signature="(ILjava/security/Key;)V",
        native=False,
    )
    def init(self, emu, opmode, key):
        self.__opmode = opmode
        # key is likely SecretKeySpec which has getEncoded()
        # But here we receive the object wrapper.
        # We need to access the python implementation to get bytes.
        # Since SecretKeySpec is python implementation, we can access internals or call getEncoded if we implemented it as method.
        # But getEncoded returns ByteArray, so we need to convert.

        # Accessing internal __key of SecretKeySpec:
        # Name mangling: _SecretKeySpec__key
        if hasattr(key, "_SecretKeySpec__key"):
            self.__key = key._SecretKeySpec__key
        else:
            logger.warning("Cipher init: Key is not SecretKeySpec or unknown structure")
            self.__key = key.getEncoded(
                emu
            ).get_py_string()  # try calling java method if wrapper

        self.__iv = None  # Reset IV

    @java_method_def(
        name="init",
        args_list=[
            "jint",
            "java/security/Key",
            "java/security/spec/AlgorithmParameterSpec",
        ],
        signature="(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
        native=False,
    )
    def init_with_params(self, emu, opmode, key, params):
        self.init(emu, opmode, key)
        # Handle IvParameterSpec
        if hasattr(params, "_IvParameterSpec__iv"):
            self.__iv = params._IvParameterSpec__iv
        else:
            logger.warning("Cipher: params not IvParameterSpec or unknown")

    @java_method_def(name="doFinal", args_list=["[B"], signature="([B)[B", native=False)
    def doFinal(self, emu, input_arr):
        data = input_arr.get_py_string()
        res = b""

        try:
            if self.__algo_name == "AES":
                mode = AES.MODE_ECB
                if self.__mode_name == "CBC":
                    mode = AES.MODE_CBC
                elif self.__mode_name == "CFB":
                    mode = AES.MODE_CFB
                # ... other modes

                if self.__iv:
                    cipher = AES.new(self.__key, mode, iv=self.__iv)
                else:
                    cipher = AES.new(self.__key, mode)

                if self.__opmode == Cipher.ENCRYPT_MODE:
                    if "Padding" in self.__padding:
                        data = pad(data, AES.block_size)
                    res = cipher.encrypt(data)
                elif self.__opmode == Cipher.DECRYPT_MODE:
                    res = cipher.decrypt(data)
                    if "Padding" in self.__padding:
                        res = unpad(res, AES.block_size)
            else:
                logger.warning(
                    f"Cipher: Algo {self.__algo_name} not implemented, returning input"
                )
                res = data
        except Exception as e:
            logger.error(f"Cipher doFinal error: {e}")
            raise e

        return ByteArray(res)
