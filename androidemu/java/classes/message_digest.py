import hashlib
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from .array import ByteArray


class MessageDigest(
    Object,
    metaclass=JavaClassDef,
    jvm_name="java/security/MessageDigest",
    jvm_super=Object,
):
    def __init__(self, algorithm):
        Object.__init__(self)
        self.__algorithm = algorithm
        self.__hash = self.__create_hash(algorithm)

    def __create_hash(self, algorithm):
        algo = algorithm.lower()
        if algo == "md5":
            return hashlib.md5()
        elif algo == "sha-1" or algo == "sha1":
            return hashlib.sha1()
        elif algo == "sha-256" or algo == "sha256":
            return hashlib.sha256()
        elif algo == "sha-512" or algo == "sha512":
            return hashlib.sha512()
        else:
            # Fallback or error
            raise ValueError(f"Unknown algorithm: {algorithm}")

    @staticmethod
    @java_method_def(
        name="getInstance",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/security/MessageDigest;",
        native=False,
    )
    def getInstance(emu, algorithm):
        return MessageDigest(algorithm.get_py_string())

    @java_method_def(name="update", args_list=["[B"], signature="([B)V", native=False)
    def update(self, emu, input):
        # input is ByteArray, get py bytes
        data = input.get_py_string()  # ByteArray.get_py_string returns bytes
        self.__hash.update(data)

    @java_method_def(
        name="update",
        args_list=["[B", "jint", "jint"],
        signature="([BII)V",
        native=False,
    )
    def update_offset(self, emu, input, offset, len):
        data = input.get_py_string()
        chunk = data[offset : offset + len]
        self.__hash.update(chunk)

    @java_method_def(name="digest", signature="()[B", native=False)
    def digest(self, emu):
        res = self.__hash.digest()
        return ByteArray(res)

    @java_method_def(name="digest", args_list=["[B"], signature="([B)[B", native=False)
    def digest_input(self, emu, input):
        self.update(emu, input)
        return self.digest(emu)

    @java_method_def(name="reset", signature="()V", native=False)
    def reset(self, emu):
        self.__hash = self.__create_hash(self.__algorithm)
