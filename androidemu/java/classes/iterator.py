from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from ...const.java_const import JAVA_NULL
from .object import Object


class Iterator(
    Object, metaclass=JavaClassDef, jvm_name="java/util/Iterator", jvm_super=Object
):
    def __init__(self, collection_iter):
        Object.__init__(self)
        self.__iter = iter(collection_iter)
        self.__next_item = None
        self.__has_next = None
        self.__advance()

    def __advance(self):
        try:
            self.__next_item = next(self.__iter)
            self.__has_next = True
        except StopIteration:
            self.__next_item = None
            self.__has_next = False

    @java_method_def(name="hasNext", signature="()Z", native=False)
    def hasNext(self, emu):
        return self.__has_next

    @java_method_def(name="next", signature="()Ljava/lang/Object;", native=False)
    def next(self, emu):
        if not self.__has_next:
            # Should throw NoSuchElementException
            return JAVA_NULL
        item = self.__next_item
        self.__advance()
        return item

    @java_method_def(name="remove", signature="()V", native=False)
    def remove(self, emu):
        # Python iterators don't support remove, unless we wrap list and index.
        raise RuntimeError("Iterator.remove not supported")
