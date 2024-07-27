import os
from pwn import *
from .context import config


def gen_sh(*a, f_or_h: str | Path = None, port: int = None, **kw) -> process | remote:
    """
    生成一个 process 或 remote 实例
    如果 config.REMOTE 为 True 则生成 remote 实例，否则生成 process 实例。

    如果传入的参数只有一个，则会将其作为 config.ATTACHMENT，如果检测到
    如果传入的参数有两个，则会将第一个参数作为 config.HOST，第二个参数作为 config.PORT。

    """
    if len(a) == 1 or (f_or_h is not None and port is None):
        s = f_or_h or a[0]
        if ":" in s and len(r := s.split(":")) == 2 and r[1].isdigit():
            config.HOST = r[0]
            config.PORT = int([1])
            config.REMOTE = True
        else:
            config.ATTACHMENT = s if isinstance(s, str) else str(s)

        if len(a) >= 1:
            a = a[1:]

    elif len(a) == 2 or (f_or_h is not None and port is not None):
        s = f_or_h or a[0]
        p = port or a[1]
        config.HOST = s
        config.PORT = p
        config.REMOTE = True

        if len(a) >= 2:
            a = a[2:]

    if config.REMOTE:
        return remote(config.HOST, config.PORT)
    if not config.ATTACHMENT.startswith(".") and not config.ATTACHMENT.startswith("/"):
        config.ATTACHMENT = "./" + config.ATTACHMENT
    if config.GDB:
        return gdb.debug(
            [config.ATTACHMENT, *config.RUNARGS.split(" ")],
            gdbscript=config.GDB_SCRIPT,
            *a,
            **kw,
        )
    return process([config.ATTACHMENT, *config.RUNARGS.split(" ")], *a, **kw)


def initialization():
    # if we're using wsl, set context terminal to cmd.exe
    if "WSL_DISTRO_NAME" in os.environ:
        args = ["cmd.exe", "/c", "start"]
        if "WT_SESSION" in os.environ:
            args.extend(["wt.exe", "-w", "0"])

            if distro_name := os.getenv("WSL_DISTRO_NAME"):
                args.extend(["wsl.exe", "-d", distro_name, "bash", "-c"])
            else:
                args.extend(["bash.exe", "-c"])

        context.terminal = args


initialization()
