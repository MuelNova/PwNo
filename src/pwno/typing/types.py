from pathlib import Path
from typing import Union

from pwn import ELF

ELFType = Union[str, Path, ELF]
