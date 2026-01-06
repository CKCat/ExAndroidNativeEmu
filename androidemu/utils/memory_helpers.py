def read_ptr_sz(mu, address, sz):
    return int.from_bytes(mu.mem_read(address, sz), byteorder="little")


def read_byte_array(mu, address, size):
    return mu.mem_read(address, size)


def read_utf8(mu, address):
    buffer_address = address
    buffer = b""
    while True:
        # Read one byte at a time to avoid OOB issues
        # efficient enough for typical emulator use
        char = mu.mem_read(buffer_address, 1)
        if char == b"\x00":
            break
        buffer += char
        buffer_address += 1

    return buffer.decode("utf-8")


def write_utf8(mu, address, value):
    value_utf8 = value.encode(encoding="utf-8")
    mu.mem_write(address, value_utf8 + b"\x00")
    return len(value_utf8) + 1


def write_ptrs_sz(mu, address, num, ptr_sz):
    if not isinstance(num, list):
        lst = [num]
    else:
        lst = num
    n = 0
    for v in lst:
        mu.mem_write(address, int(v).to_bytes(ptr_sz, byteorder="little"))
        address += ptr_sz
        n += ptr_sz

    return n
