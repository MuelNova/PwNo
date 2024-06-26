import subprocess
from pathlib import Path
from pwn import *
from elftools.common.exceptions import ELFError
from argparse import ArgumentParser
from pydantic import BaseModel, root_validator, ValidationError, validator

# ------- Default Settings -------
class Config(BaseModel, extra='ignore'):
    ATTACHMENT: str = None
    RUNARGS: str = ''
    LIBC: str = '/lib/x86_64-linux-gnu/libc.so.6'
    HOST: str = ''
    PORT: int = 0

    NO_DEBUG: bool = False
    REMOTE: bool = False
    GDB: bool = False  # gdb.debug(elf.path, gdbscript=gdbscript)
    GDB_SCRIPT: str = ''
    DBG: list[int] = None

    @root_validator(pre=True)
    def ignore_None(cls, values):
        fin = {k: v for k, v in values.items() if v is not None}
        keys = list(fin.keys())
        if ('HOST' in keys and 'PORT' not in keys) \
            or \
            ('PORT' in keys and 'HOST' not in keys):
            raise ValidationError(f"Host and Port should be both set.")


        if 'REMOTE' in fin.keys():
            rmt = values['REMOTE'].split(':')
            fin['HOST'] = rmt[0]
            fin['PORT'] = int(rmt[1])
            fin['REMOTE'] = True
        return fin

    @validator('ATTACHMENT', pre=True, always=True)
    def _attachment(cls, value) -> str:
        if value is None:
            def is_elf(path: Path):
                try:
                    result = subprocess.run(['file', str(path)], capture_output=True, text=True)
                    return "ELF" in result.stdout and "executable" in result.stdout
                except:
                    return False
            for file in Path.cwd().iterdir():
                if file.is_file() and is_elf(file):
                    info("No Attachment set, using \"%s\"...", file.absolute())
                    return str(file.absolute())
            return '/bin/sh'  # fallback
        return value
    
    @validator('DBG', pre=True, always=True)
    def _dbg(cls, value) -> list[int]:
        if value is None:
            return []
        return [int(i) for i in value.split(',')]
    
    @validator('GDB_SCRIPT', pre=True, always=True)
    def _gdb_script(cls, value) -> str:
        if value is None:
            return ''
        if Path(value).is_file():
            return Path(value).read_text()
        return value.replace('\\n', '\n')

parser = ArgumentParser(description="Pwnable Commandline")
parser.add_argument('ATTACHMENT', nargs='?')
parser.add_argument('--libc', '-l', nargs='?', dest='LIBC')
parser.add_argument('--debug', '-d', action='store', dest='DBG', help='Which dbg() to be executed, default is `all`, use comma to split. e.g. `-d 0,1,3`')
parser.add_argument('--no-debug', '-D', action='store_true', dest='NO_DEBUG', help='Disable debug mode')
parser.add_argument('--remote', '-r', action='store', dest='REMOTE', help='Remote host:port')
parser.add_argument('--host', '-H', action='store', dest='HOST', help='Remote host, if remote is set, this option will be ignored')
parser.add_argument('--port', '-p', action='store', dest='PORT', help='Remote port, if remote is set, this option will be ignored')
parser.add_argument('--gdb', '-g', action='store_true', dest='GDB', help='Run binary using gdb.debug')
parser.add_argument('--gdb-script', '-G', action='store', dest='GDB_SCRIPT', help='GDB script to run')
parser.add_argument('--args', '-a', action='store', dest='RUNARGS', help='Arguments to run binary')
args = parser.parse_args()

config = Config(**vars(args))
try:
    elf = ELF(config.ATTACHMENT)
    context.arch = elf.arch
except ELFError:
    elf = None
    log.warning(f"{config.ATTACHMENT} is not a valid ELF file!, `elf` is not set")
libc = ELF(config.LIBC)

context.log_level = 'debug'
context.os = 'linux'
