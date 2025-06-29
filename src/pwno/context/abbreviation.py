import inspect
from typing import Any, Callable, Tuple, TypeVar, ParamSpec, Concatenate

from pwn import process, remote

T = TypeVar("T", bound=Callable[..., Any])
P = ParamSpec("P")
R = TypeVar("R")

_INSTANCE_CACHE: dict[int, tuple[str, process | remote]] = {}
_CACHE_TIMEOUT = 100


def _find_instance_in_frame(ctx, name: str) -> tuple[str, process | remote] | None:
    """在指定栈帧中查找实例"""
    if ctx is None:
        return None

    locals_items = ctx.f_locals.items()

    if not name:
        # 按插入顺序反向搜索最新实例
        for k, v in reversed(locals_items):
            if isinstance(v, (process, remote)) and _is_instance_valid(v):
                return k, v
    else:
        # 查找指定名称的实例
        if name in ctx.f_locals:
            v = ctx.f_locals[name]
            if isinstance(v, (process, remote)) and _is_instance_valid(v):
                return name, v

    return None


def get_instance(name: str = "", start: int = 1) -> Tuple[str, process | remote]:
    """
    拿取 process/remote 实例，如果没有传入 name 则会自动寻找
    当前上下文中最新的一个 process/remote 实例。
    参数：
        name(str): 需要拿取的 process/remote 实例的名字
        start(int): 从第几层开始寻找，0 为当前栈，1 为上一栈帧，以此类推。
    返回：
        (name, instance): name 为实例的名字，instance 为实例本身
    """
    ctx = inspect.currentframe()
    if ctx is None:
        raise ValueError("No current frame found")

    # fastpath
    if name:
        cache_key = hash((name, id(ctx.f_back)))
        if cache_key in _INSTANCE_CACHE:
            cached_name, cached_instance = _INSTANCE_CACHE[cache_key]
            if cached_name == name and _is_instance_valid(cached_instance):
                return cached_name, cached_instance

    # 移动到指定的起始栈帧
    for _ in range(start):
        ctx = ctx.f_back
        if ctx is None:
            break

    # 在栈帧中搜索实例
    while ctx is not None:
        result = _find_instance_in_frame(ctx, name)
        if result:
            instance_name, instance = result
            # 缓存结果
            cache_key = hash((instance_name, id(ctx)))
            _INSTANCE_CACHE[cache_key] = (instance_name, instance)
            _cleanup_cache()
            return instance_name, instance
        ctx = ctx.f_back

    raise ValueError("No instance found")


def _is_instance_valid(instance: process | remote) -> bool:
    """检查实例是否有效"""
    if isinstance(instance, process):
        return instance.poll() is None
    elif isinstance(instance, remote):
        return not (instance.closed["send"] or instance.closed["recv"])
    return False


def _cleanup_cache():
    if len(_INSTANCE_CACHE) > _CACHE_TIMEOUT:
        keys_to_remove = list(_INSTANCE_CACHE.keys())[: len(_INSTANCE_CACHE) // 2]
        for key in keys_to_remove:
            del _INSTANCE_CACHE[key]


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
    # 预计算函数名和实例名，避免运行时计算
    method_name = func.__name__
    instance_name = ""

    if inspect.ismethod(func):
        ctx = inspect.currentframe()
        while ctx is not None and not instance_name:
            ctx = ctx.f_back
            if ctx is None:
                break
            for k, v in reversed(ctx.f_locals.items()):
                if v is func.__self__:
                    instance_name = k
                    break

    # 使用实例缓存
    cached_instance = None
    cache_valid_count = 0

    def inner(*args: P.args, **kwargs: P.kwargs) -> R:
        nonlocal cached_instance, cache_valid_count

        # 检查缓存的实例是否仍然有效
        if (
            cached_instance is None
            or not _is_instance_valid(cached_instance)
            or cache_valid_count <= 0
        ):
            # 获取新实例
            _, cached_instance = get_instance(instance_name, start=2)
            cache_valid_count = _CACHE_TIMEOUT

        # 减少缓存计数
        cache_valid_count -= 1

        # 直接调用方法，避免 getattr 开销
        method = getattr(cached_instance, method_name)
        return method(*args, **kwargs)

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
