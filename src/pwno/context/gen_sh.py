import os
from pwn import *
from .context import config

def gen_sh(*a, **kw) -> process | remote:
    if config.REMOTE:
        return remote(config.HOST, config.PORT)
    if config.GDB:
        return gdb.debug([config.ATTACHMENT, *config.RUNARGS.split(' ')], gdbscript=config.GDB_SCRIPT, *a, **kw)
    return process([config.ATTACHMENT, *config.RUNARGS.split(' ')], *a, **kw)


def initialization():
    # if we're using wsl, set context terminal to cmd.exe
    if "WSL_DISTRO_NAME" in os.environ:
        args = ['cmd.exe', '/c', 'start']
        if 'WT_SESSION' in os.environ:
                args.extend(['wt.exe', '-w', '0', 'split-pane', '-d', '.'])

                if distro_name := os.getenv('WSL_DISTRO_NAME'):
                    args.extend(['wsl.exe', '-d', distro_name, 'bash', '-c'])
                else:
                    args.extend(['bash.exe', '-c'])

        context.terminal = args

initialization()
