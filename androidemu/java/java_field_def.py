from .jvm_id_conter import next_field_id


class JavaFieldDef:
    def __init__(
        self,
        name: str,
        signature: str,
        is_static: bool,
        static_value=None,
        ignore: bool = False,
    ):
        self.jvm_id = next_field_id()
        self.name = name
        self.signature = signature
        self.is_static = is_static
        self.static_value = static_value
        self.ignore = ignore

        if self.is_static and self.static_value is None:
            raise ValueError("Static value may not be None for a static field.")
