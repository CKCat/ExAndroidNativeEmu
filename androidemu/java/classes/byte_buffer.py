from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def
from .object import Object
from ...const.java_const import JAVA_NULL


class Buffer(
    Object, metaclass=JavaClassDef, jvm_name="java/nio/Buffer", jvm_super=Object
):
    def __init__(self, address, capacity):
        Object.__init__(self)
        self._address = address
        self._capacity = capacity
        self._position = 0
        self._limit = capacity

    @java_method_def(name="capacity", signature="()I", native=False)
    def capacity(self, emu):
        return self._capacity

    @java_method_def(name="position", signature="()I", native=False)
    def position(self, emu):
        return self._position

    @java_method_def(name="limit", signature="()I", native=False)
    def limit(self, emu):
        return self._limit


class ByteBuffer(
    Buffer, metaclass=JavaClassDef, jvm_name="java/nio/ByteBuffer", jvm_super=Buffer
):
    def __init__(self, address, capacity):
        Buffer.__init__(self, address, capacity)
        self._order = "BIG_ENDIAN"  # Default Java

    @java_method_def(
        name="order",
        signature="(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;",
        args_list=["jobject"],
        native=False,
    )
    def order(self, emu, byte_order):
        # byte_order is a ByteOrder object.
        # We might need to inspect it.
        # For now just ignore or assume set.
        return self

    @staticmethod
    @java_method_def(
        name="allocate",
        signature="(I)Ljava/nio/ByteBuffer;",
        args_list=["jint"],
        native=False,
    )
    def allocate(emu, capacity):
        # In real Java this returns a HeapByteBuffer.
        # We can simulate heap by allocating memory in emulator?
        # Or just Python bytearray?
        # But JNI NewDirectByteBuffer wraps Native Memory.
        # allocate() wraps Java Array.

        # Implementation: Allocate native memory (malloc style) effectively making it "Direct" for simplicity?
        # Or distinguishable?
        # Let's allocate native memory to handle it uniformly for now,
        # or implement HeapByteBuffer separately.
        # Stub:
        return JAVA_NULL

    @staticmethod
    @java_method_def(
        name="allocateDirect",
        signature="(I)Ljava/nio/ByteBuffer;",
        args_list=["jint"],
        native=False,
    )
    def allocateDirect(emu, capacity):
        # native allocation
        heap = emu.mu.mem_map(
            0, capacity
        )  # This is wrong, mem_map needs aligned size and address usually.
        # Better: use malloc if we had a heap allocator.
        # Since we have brk, we can't easily "malloc" small chunks unless we have a malloc impl.
        # Fallback: Just stub or fail.
        return JAVA_NULL


# Internal implementation for JNI NewDirectByteBuffer
class DirectByteBuffer(
    ByteBuffer,
    metaclass=JavaClassDef,
    jvm_name="java/nio/DirectByteBuffer",
    jvm_super=ByteBuffer,
):
    def __init__(self, address, capacity):
        ByteBuffer.__init__(self, address, capacity)
