class jobject:
    def __init__(self, value: object = None):
        self.value = value


class jclass(jobject):
    def __init__(self, value: object = None):
        super().__init__(value)
