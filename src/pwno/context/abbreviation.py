import inspect

from typing import TypeVar, Callable, Any
from pwn import pwnlib, process

T = TypeVar('T', bound=Callable[..., Any])
def abbr(func: T) -> T:
    """
    提供一个函数的缩写，如果传入类则默认找到当前上下文中最新的一个实例(process/remote)。
    参数：
          func(Callable)
            需要缩写的函数，可以是类的方法或者普通函数，例如
            ``process.sendline`` 或 ``p.sendline``。
            对于前者，将会自动寻找当前上下文中最新的一个 process/remote 实例，并调用其 sendline 方法
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
        for k, v in reversed(inspect.currentframe().f_back.f_locals.items()):
            if v == func.__self__:
                name = k
                break
    else:
        name = ''

    def get_instance(force=False):
        nonlocal name
        ctx = inspect.currentframe().f_back.f_back.f_locals
        if name == '' or force:
            for k, v in reversed(ctx.items()):
                if isinstance(v, (pwnlib.tubes.process.process, pwnlib.tubes.remote.remote)):
                    name = k
                    break
        return ctx[name]
    
    def inner(*args, **kwargs):
        sh = get_instance()
        if sh.poll() is not None:
            sh = get_instance(True)
        return getattr(sh, f)(*args, **kwargs)
    return inner

sl = abbr(process.sendline)
recv = abbr(process.recv)