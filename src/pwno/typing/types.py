from typing import Union
from pathlib import Path
from pwn import ELF

ELFType = Union[str, Path, ELF]
