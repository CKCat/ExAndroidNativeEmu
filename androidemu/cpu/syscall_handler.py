from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class SyscallHandler:
    idx: int
    name: str
    arg_count: int
    callback: Callable[..., Any]
