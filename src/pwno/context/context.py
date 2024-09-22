import subprocess
from argparse import ArgumentParser
from pathlib import Path

from elftools.common.exceptions import ELFError
from pwn import *
from pydantic import (
    BaseModel,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)
from typing_extensions import Annotated


# ------- Default Settings -------
class Config(BaseModel, extra="ignore"):
    ATTACHMENT: Annotated[str, Field(validate_default=True)] = None
    RUNARGS: str = ""
    LIBC: Annotated[str, Field(validate_default=True)] = None
    HOST: str = ""
    PORT: int = 0

    NO_DEBUG: bool = False
    REMOTE: bool = False
    GDB: bool = False  # gdb.debug(elf.path, gdbscript=gdbscript)
    GDB_SCRIPT: Annotated[str, Field(validate_default=True)] = None
    DBG: Annotated[list[int], Field(validate_default=True)] = None

    @field_validator("ATTACHMENT", mode="before")
    def _attachment(cls, value) -> str:
        if value is None:

            def is_elf(path: Path):
                try:
                    result = subprocess.run(
                        ["file", str(path)], capture_output=True, text=True
                    )
                    return "ELF" in result.stdout and "executable" in result.stdout
                except Exception:
                    return False

            for file in Path.cwd().iterdir():
                if file.is_file() and is_elf(file):
                    return str(file.absolute())
            return "/bin/sh"  # fallback
        return value

    @field_validator("DBG", mode="before")
    def _dbg(cls, value) -> list[int]:
        if value is None:
            return []
        return [int(i) for i in value.split(",")]

    @field_validator("GDB_SCRIPT", mode="before")
    def _gdb_script(cls, value) -> str:
        if value is None:
            return ""
        if Path(value).is_file():
            return Path(value).read_text()
        return value.replace("\\n", "\n")

    @field_validator("LIBC", mode="before")
    def _libc(cls, value: str | None, info_: ValidationInfo) -> str:
        if value is None:
            output_raw = subprocess.run(
                ["ldd", info_.data.get("ATTACHMENT", "/bin/sh")],
                capture_output=True,
                text=True,
            ).stdout.split("\n")
            output = filter(lambda x: "libc" in x, output_raw)
            libc_path = None
            for line in output:
                libc_path = next(
                    filter(
                        lambda x: Path(x).is_file(), line.strip("\t").strip().split(" ")
                    ),
                    None,
                )
                if libc_path:
                    break
            return libc_path
        return value

    @model_validator(mode="before")
    def ignore_None(cls, values):
        fin = {k: v for k, v in values.items() if v is not None}
        keys = list(fin.keys())
        if ("HOST" in keys and "PORT" not in keys) or (
            "PORT" in keys and "HOST" not in keys
        ):
            raise ValidationError("Host and Port should be both set.")

        if "REMOTE" in fin.keys():
            rmt = values["REMOTE"].split(":")
            fin["HOST"] = rmt[0]
            fin["PORT"] = int(rmt[1])
            fin["REMOTE"] = True
        return fin


def default_main():
    parser = ArgumentParser(description="Pwnable Commandline")

    parser.add_argument("ATTACHMENT", nargs="?")
    parser.add_argument("--libc", "-l", nargs="?", dest="LIBC")
    parser.add_argument(
        "--debug",
        "-d",
        action="store",
        dest="DBG",
        help=(
            "Which dbg() to be executed, default is `all`"
            "use comma to split. e.g. `-d 0,1,3`"
        ),
    )
    parser.add_argument(
        "--no-debug",
        "-D",
        action="store_true",
        dest="NO_DEBUG",
        help="Disable debug mode",
    )
    parser.add_argument(
        "--remote", "-r", action="store", dest="REMOTE", help="Remote host:port"
    )
    parser.add_argument(
        "--host",
        "-H",
        action="store",
        dest="HOST",
        help="Remote host, if remote is set, this option will be ignored",
    )
    parser.add_argument(
        "--port",
        "-p",
        action="store",
        dest="PORT",
        help="Remote port, if remote is set, this option will be ignored",
    )
    parser.add_argument(
        "--gdb",
        "-g",
        action="store_true",
        dest="GDB",
        help="Run binary using gdb.debug",
    )
    parser.add_argument(
        "--gdb-script",
        "-G",
        action="store",
        dest="GDB_SCRIPT",
        help="GDB script to run",
    )
    parser.add_argument(
        "--args", "-a", action="store", dest="RUNARGS", help="Arguments to run binary"
    )
    parser.add_argument(
        "--checksec", "-c", action="store_true", help="Check security of the binary"
    )

    args = parser.parse_args()

    global config, Elf, libc
    config = Config(**vars(args))

    if not args.ATTACHMENT:
        info('No Attachment set, using "%s"...', config.ATTACHMENT)
    if not args.LIBC:
        info('No Libc set, using "%s"...', config.LIBC)

    try:
        Elf = ELF(config.ATTACHMENT, checksec=args.checksec)
        context.arch = Elf.arch
    except ELFError:
        Elf = None
        log.warning(f"{config.ATTACHMENT} is not a valid ELF file!, `Elf` is not set")
    try:
        libc = ELF(config.LIBC, checksec=args.checksec)
    except ELFError:
        libc = None
        log.warning(f"{config.LIBC} is not a valid ELF file!, `libc` is not set")


def get_config() -> Config:
    return config if config else Config()


config: Config = None
Elf: ELF = None
libc: ELF = None

context.log_level = "debug"
context.os = "linux"
