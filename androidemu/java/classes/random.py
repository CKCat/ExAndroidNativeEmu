from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
import random


class Random(
    Object, metaclass=JavaClassDef, jvm_name="java/util/Random", jvm_super=Object
):
    def __init__(self, seed=None):
        Object.__init__(self)
        self.__rng = random.Random(seed)

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        self.__rng = random.Random()

    @java_method_def(name="<init>", args_list=["jlong"], signature="(J)V", native=False)
    def ctor_seed(self, emu, seed):
        self.__rng = random.Random(seed)

    @java_method_def(
        name="setSeed", args_list=["jlong"], signature="(J)V", native=False
    )
    def setSeed(self, emu, seed):
        self.__rng.seed(seed)

    @java_method_def(name="nextInt", signature="()I", native=False)
    def nextInt(self, emu):
        return self.__rng.randint(-2147483648, 2147483647)

    @java_method_def(name="nextInt", args_list=["jint"], signature="(I)I", native=False)
    def nextIntBound(self, emu, bound):
        if bound <= 0:
            raise ValueError("bound must be positive")
        return self.__rng.randint(0, bound - 1)

    @java_method_def(name="nextLong", signature="()J", native=False)
    def nextLong(self, emu):
        return self.__rng.randint(-9223372036854775808, 9223372036854775807)

    @java_method_def(name="nextBoolean", signature="()Z", native=False)
    def nextBoolean(self, emu):
        return bool(self.__rng.getrandbits(1))

    @java_method_def(name="nextFloat", signature="()F", native=False)
    def nextFloat(self, emu):
        return self.__rng.random()

    @java_method_def(name="nextDouble", signature="()D", native=False)
    def nextDouble(self, emu):
        return self.__rng.random()
