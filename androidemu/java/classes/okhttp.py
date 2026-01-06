from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def


class Buffer(metaclass=JavaClassDef, jvm_name="okio/Buffer"):
    def __init__(self):
        self.__buffer = bytearray()

    @java_method_def(name="<init>", signature="()V", native=False)
    def init(self, emu):
        pass

    @java_method_def(
        name="writeString",
        args_list=["jstring", "jobject"],
        signature="(Ljava/lang/String;Ljava/nio/charset/Charset;)Lokio/Buffer;",
        native=False,
    )
    def writeString(self, emu, string, charset):
        # py_string = string.get_py_string()
        # self.__buffer.extend(py_string.encode('utf-8')) # Using utf-8 as default for now
        if charset:
            # Charset handling is simplified here
            pass
        self.__buffer.extend(string.get_py_string().encode("utf-8"))
        return self

    @java_method_def(name="readByteArray", signature="()[B", native=False)
    def readByteArray(self, emu):
        from .array import ByteArray

        return ByteArray(self.__buffer)

    @java_method_def(
        name="read", args_list=["jobject"], signature="([B)I", native=False
    )
    def read(self, emu, array):
        # array is ByteArray
        size = len(array)
        read_data = self.__buffer[:size]
        self.__buffer = self.__buffer[size:]

        # Write back to array
        # Assuming array is ByteArray which wraps a mutable sequence (bytearray or list)
        items = array.get_py_items()
        limit = min(len(items), len(read_data))
        items[:limit] = read_data[:limit]

        return len(read_data)

    @java_method_def(name="close", signature="()V", native=False)
    def close(self, emu):
        pass

    @java_method_def(name="clone", signature="()Lokio/Buffer;", native=False)
    def clone(self, emu):
        new_buf = Buffer()
        new_buf.__buffer = bytearray(self.__buffer)
        return new_buf


class ResponseBody(metaclass=JavaClassDef, jvm_name="okhttp3/ResponseBody"):
    def __init__(self):
        pass

    @java_method_def(name="string", signature="()Ljava/lang/String;", native=False)
    def string(self, emu):
        from .string import String

        return String("")


class Builder(metaclass=JavaClassDef, jvm_name="okhttp3/Request$Builder"):
    def __init__(self):
        self.__headers = Headers()
        self.__url = ""

    @java_method_def(
        name="header",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;",
        native=False,
    )
    def header(self, emu, skey, svalue):
        key = skey.get_py_string()
        value = svalue.get_py_string()
        self.__headers._Headers__headers[key] = value
        return self

    @java_method_def(
        name="url",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Lokhttp3/Request$Builder;",
        native=False,
    )
    def url(self, emu, url):
        self.__url = url.get_py_string()
        return self

    @java_method_def(name="build", signature="()Lokhttp3/Request;", native=False)
    def build(self, emu):
        return Request(self.__url, self.__headers)


class HttpUrl(metaclass=JavaClassDef, jvm_name="okhttp3/HttpUrl"):
    def __init__(self, url_string):
        self.__url = url_string

    @java_method_def(name="encodedPath", signature="()Ljava/lang/String;", native=False)
    def encodedPath(self, emu):
        from .string import String

        # Simple/naive implementation
        if "://" in self.__url:
            path = self.__url.split("://", 1)[1]
            if "/" in path:
                return String("/" + path.split("/", 1)[1].split("?", 1)[0])
        return String("/")

    @java_method_def(
        name="encodedQuery", signature="()Ljava/lang/String;", native=False
    )
    def encodedQuery(self, emu):
        from .string import String

        if "?" in self.__url:
            return String(self.__url.split("?", 1)[1])
        return None


class RequestBody(metaclass=JavaClassDef, jvm_name="okhttp3/RequestBody"):
    def __init__(self):
        pass

    @java_method_def(
        name="writeTo",
        args_list=["jobject"],
        signature="(Lokio/BufferedSink;)V",
        native=False,
    )
    def writeTo(self, emu, buffer):
        pass


class Headers(metaclass=JavaClassDef, jvm_name="okhttp3/Headers"):
    def __init__(self, headers=None):
        self.__headers = headers if headers else {}

    @java_method_def(
        name="values",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/util/List;",
        native=False,
    )
    def values(self, emu, jstr):
        from .list import List

        return List([])

    @java_method_def(name="size", signature="()I", native=False)
    def size(self, emu):
        return len(self.__headers)

    @java_method_def(
        name="name",
        args_list=["jint"],
        signature="(I)Ljava/lang/String;",
        native=False,
    )
    def name(self, emu, i):
        from .string import String

        keys = list(self.__headers.keys())
        if 0 <= i < len(keys):
            return String(keys[i])
        return None

    @java_method_def(
        name="value",
        args_list=["jint"],
        signature="(I)Ljava/lang/String;",
        native=False,
    )
    def value(self, emu, i):
        from .string import String

        keys = list(self.__headers.keys())
        if 0 <= i < len(keys):
            return String(str(self.__headers[keys[i]]))
        return None


class Request(metaclass=JavaClassDef, jvm_name="okhttp3/Request"):
    def __init__(self, url_path, headers):
        from .string import String

        if isinstance(url_path, String):
            url_path = url_path.get_py_string()
        self.__url_object = HttpUrl(url_path)
        self.__headers_object = (
            headers if isinstance(headers, Headers) else Headers(headers)
        )

    @java_method_def(name="url", signature="()Lokhttp3/HttpUrl;", native=False)
    def url(self, emu):
        return self.__url_object

    @java_method_def(name="body", signature="()Lokhttp3/RequestBody;", native=False)
    def body(self, emu):
        return RequestBody()

    @java_method_def(name="headers", signature="()Lokhttp3/Headers;", native=False)
    def headers(self, emu):
        return self.__headers_object

    @java_method_def(
        name="newBuilder", signature="()Lokhttp3/Request$Builder;", native=False
    )
    def newBuilder(self, emu):
        return Builder()


class Response(metaclass=JavaClassDef, jvm_name="okhttp3/Response"):
    def __init__(self):
        pass

    @java_method_def(name="code", signature="()I", native=False)
    def code(self, emu):
        return 200

    @java_method_def(name="body", signature="()Lokhttp3/ResponseBody;", native=False)
    def body(self, emu):
        return ResponseBody()

    @java_method_def(name="close", signature="()V", native=False)
    def close(self, emu):
        pass

    @java_method_def(
        name="header",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/String;",
        native=False,
    )
    def header(self, emu, skey):
        from .string import String

        return String("")


class Chain(metaclass=JavaClassDef, jvm_name="okhttp3/Interceptor$Chain"):
    def __init__(self, req):
        self.__req = req
        self.__req_after_proceed = None

    @java_method_def(name="request", signature="()Lokhttp3/Request;", native=False)
    def request(self, emu):
        return self.__req

    @java_method_def(
        name="proceed",
        args_list=["jobject"],
        signature="(Lokhttp3/Request;)Lokhttp3/Response;",
        native=False,
    )
    def proceed(self, emu, req):
        self.__req_after_proceed = req
        self.__req_after_proceed = req
        # Warning: Returning empty/mock response as actual network is not simulated.
        return Response()

    def get_proceed_request(self):
        return self.__req_after_proceed
