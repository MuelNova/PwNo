from typing import Literal, Any
from pwn import *
from ..context import config, get_instance

def uu64(data: bytes, endianness: Literal['little', 'big'] = None, sign: bool = None, **kwargs: Any):
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
    return pwnlib.util.packing.u64(data.ljust(8, b'\x00'), endianness=endianness, sign=sign, **kwargs)


def uu32(data: bytes, endianness: Literal['little', 'big'] = None, sign: bool = None, **kwargs: Any):
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
    return pwnlib.util.packing.u32(data.ljust(4, b'\x00'), endianness=endianness, sign=sign, **kwargs)


def dbg(gdb_script: str = None,
        sh: process | remote = None,
        s: int = 4, force: bool = False):
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
    if (config.REMOTE or config.GDB) and not force:
        return
    if sh is None:
        sh = get_instance()
        if isinstance(sh, remote) and not force:
            return
    gdb.attach(sh, gdb_script)
    if s != 0 and not config.GDB:
        pause(s)
