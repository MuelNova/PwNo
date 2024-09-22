import inspect
from pathlib import Path

from pwno.context import *
from pwno.typing import *
from pwno.helper import *

frame = inspect.currentframe()
while frame.f_back:
    frame = frame.f_back


if Path(frame.f_globals["__file__"]).name != "pwno":
    default_main()

config = get_config()
