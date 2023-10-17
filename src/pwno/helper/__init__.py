from typing import Literal, Any
from pwn import *

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
