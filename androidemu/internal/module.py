from loguru import logger


class Module:
    def __init__(
        self,
        filename: str,
        address: int,
        size: int,
        symbols_resolved,
        init_array,
        soinfo_ptr,
    ):
        self.filename = filename
        self.base = address
        self.size = size
        self.symbols = symbols_resolved
        self.symbol_lookup = dict()
        self.init_array = list(init_array)
        self.soinfo_ptr = soinfo_ptr

        # Create fast lookup.
        for symbol_name in self.symbols:
            addr = self.symbols[symbol_name]
            if addr != 0:
                self.symbol_lookup[addr] = symbol_name

    def find_symbol(self, name):
        if name in self.symbols:
            return self.symbols[name]
        return None

    def is_symbol_addr(self, addr):
        if addr in self.symbol_lookup:
            return self.symbol_lookup[addr]
        elif addr + 1 in self.symbol_lookup:
            return self.symbol_lookup[addr + 1]
        else:
            return None

    def call_init(self, emu):
        for fun_ptr in self.init_array:
            fun_addr = fun_ptr
            logger.debug(
                f"Calling Init_array {self.filename} function: 0x{fun_addr:08X} "
            )
            emu.call_native(fun_addr)
