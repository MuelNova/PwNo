import inspect
from pathlib import Path

from pwno.context import *
from pwno.helper import *
from pwno.typing import *

frame = inspect.currentframe()
while frame.f_back:
    frame = frame.f_back


if Path(frame.f_globals["__file__"]).name != "pwno":
    default_main()

