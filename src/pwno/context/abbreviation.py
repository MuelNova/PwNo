import inspect
from typing import Any, Callable, Tuple, TypeVar, ParamSpec, Concatenate

from pwn import process, remote

T = TypeVar("T", bound=Callable[..., Any])
P = ParamSpec("P")
R = TypeVar("R")


def get_instance(name: str = "", start: int = 1) -> Tuple[str, process | remote]:
    """
    拿取 process/remote 实例，如果没有传入 name 则会自动寻找
    当前上下文中最新的一个 process/remote 实例。
    参数：
        name(str)
            需要拿取的 process/remote 实例的名字
        force(bool)
            如果为 True，则会强制寻找当前上下文中最新的
            一个 process/remote 实例而不是传入的 name
        start(int)
            从第几层开始寻找，0 为当前栈，1 为上一栈帧，以此类推。
    返回：
        (name, instance)
            name 为实例的名字，instance 为实例本身
    """
    ctx = inspect.currentframe()
    if ctx is None:
        raise ValueError("No current frame found")
    for _ in range(start):
        ctx = ctx.f_back
        if ctx is None:
            break
    while ctx is not None:
        for k, v in reversed(ctx.f_locals.items()):
            if isinstance(v, (process, remote)):
                if name is not None:
                    if k == name:
                        return k, v
                    else:
                        continue
                return k, v
        ctx = ctx.f_back
    raise ValueError("No instance found")


def abbr(func: Callable[Concatenate[Any, P], R]) -> Callable[P, R]:
    """
    提供一个函数的缩写，如果传入类则默认找到当前上下文中最新的一个实例(process/remote)。

    这个函数会移除方法的 self 参数，将实例方法转换为独立函数。

    参数：
          func(Callable)
            需要缩写的函数，可以是类的方法或者普通函数，例如
            ``process.sendline`` 或 ``p.sendline``。

            对于前者，将会自动寻找当前上下文中最新的一个 process/remote 实例
            并调用其 sendline 方法

            对于后者，将会调用 p 的 sendline 方法

    默认提供了以下缩写，这些函数将使用 *最新* 的 process/remote 实例。
        >>> send  = process.send
        >>> sl = process.sendline
        >>> sa = process.sendafter
        >>> sla = process.sendlineafter

        >>> recv = process.recv
        >>> recvu = process.recvuntil
        >>> recvn = process.recvn
        >>> recvl = process.recvline

        >>> ia = process.interactive
    """
    f = func.__name__
    if inspect.ismethod(func):
        ctx = inspect.currentframe()
        flag = False
        while ctx is not None and not flag:
            ctx = ctx.f_back
            if ctx is None:
                break
            for k, v in reversed(ctx.f_locals.items()):
                if v == func.__self__:
                    name = k
                    flag = True
                    break
    else:
        name = ""
    sh = None

    def inner(*args: P.args, **kwargs: P.kwargs) -> R:
        nonlocal sh
        if (
            sh is None
            or (isinstance(sh, process) and sh.poll() is not None)
            or (isinstance(sh, remote) and (sh.closed["send"] or sh.closed["recv"]))
        ):
            # sh.poll() is not None means the process is closed
            _, sh = get_instance(name, start=2)
        # print(name, sh, sh.proc, sh.proc.pid)
        return getattr(sh, f)(*args, **kwargs)

    return inner


send = abbr(process.send)
sl = abbr(process.sendline)
sa = abbr(process.sendafter)
sla = abbr(process.sendlineafter)

recv = abbr(process.recv)
recvu = abbr(process.recvuntil)
recvn = abbr(process.recvn)
recvl = abbr(process.recvline)

ia = abbr(process.interactive)
