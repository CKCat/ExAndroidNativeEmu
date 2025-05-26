class SyscallHandler:
    def __init__(self, idx: int, name: str, arg_count: int, callback: callable):
        self.idx = idx
        self.name = name
        self.arg_count = arg_count
        self.callback = callback
