from typing import Callable, Literal, Any
from sorcery import spell, args_with_source
from sorcery.core import FrameInfo
from functools import partial
from pwn import remote, process, gdb, pause, pwnlib, hexdump
from pwn import (
    success as _success,
    info as _info,
    debug as _debug,
    warning as _warning,
    warn as _warn,
    error as _error,
)
from ..context import config, get_instance

DBG_CNT = -1


def uu64(
    data: bytes,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Unpacks 64-bit integer from padded data.

    endianness and signedness is done according to context.

    Arguments:
        data (bytes): Data to unpack from
        endianness (str): Endianness of the integer ("little"/"big")
        sign (bool): Signedness of the integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The unpacked integer.
    """
    return pwnlib.util.packing.u64(
        data.ljust(8, b"\x00"), endianness=endianness, sign=sign, **kwargs
    )


def uu32(
    data: bytes,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Unpacks 32-bit integer from padded data.

    endianness and signedness is done according to context.

    Arguments:
        data (bytes): Data to unpack from
        endianness (str): Endianness of the integer ("little"/"big")
        sign (bool): Signedness of the integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The unpacked integer.
    """
    return pwnlib.util.packing.u32(
        data.ljust(4, b"\x00"), endianness=endianness, sign=sign, **kwargs
    )


def dbg(
    gdb_script: str = None,
    sh: process | remote | None = None,
    s: int = 4,
    force: bool = False,
):
    """
    附加 GDB，默认选择最新的 process
    参数：
        gdb_script(str)
            GDB 调试参数，用 \n 分割
        sh(process | remote)
            指定附加的 sh
        s(int)
            等待时间，在 attach 上进程后等待多少秒，默认为 4s
        force(bool)
            强制调试 gdb.debug() 的实例或是 remote 实例
    """
    if (config.REMOTE or config.GDB or config.NO_DEBUG) and not force:
        return
    if sh is None:
        _, sh = get_instance()
        if isinstance(sh, remote) and not force:
            return

    global DBG_CNT
    DBG_CNT += 1
    if config.DBG and DBG_CNT not in config.DBG:
        return
    gdb.attach(sh, gdb_script)
    if not config.GDB:
        if s == -1:
            return
        if s == 0:
            pause()
        else:
            pause(s)


def __pplog(
    frame_info: FrameInfo,
    func: Callable[[Any], None],
    msg: Any,
    *args: Any,
    **kwargs: Any,
):
    for source, arg in args_with_source.at(frame_info)(msg, *args, kwargs):
        if isinstance(arg, int):
            func(f"{source}: {arg:#x}({arg})")
        elif isinstance(arg, bytes):
            func(f"{source}\n{hexdump(arg)}")
        else:
            func(f"{source}: {arg}")


success: Callable[[Any], None] = partial(spell(__pplog), _success)
info: Callable[[Any], None] = partial(spell(__pplog), _info)
debug: Callable[[Any], None] = partial(spell(__pplog), _debug)
warning: Callable[[Any], None] = partial(spell(__pplog), _warning)
warn: Callable[[Any], None] = partial(spell(__pplog), _warn)
error: Callable[[Any], None] = partial(spell(__pplog), _error)
