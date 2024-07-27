from typing import Literal, Any
from pwn import pwnlib


def p64(
    number: int,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Packs integer into wordsize of 64.

    endianness and signedness is done according to context.

    Arguments:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (bool): Signedness of the converted integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The packed number as a byte.
    """
    return pwnlib.util.packing.p64(number, endianness=endianness, sign=sign, **kwargs)


def p32(
    number: int,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Packs integer into wordsize of 32.

    endianness and signedness is done according to context.

    Arguments:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (bool): Signedness of the converted integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The packed number as a byte.
    """
    return pwnlib.util.packing.p32(number, endianness=endianness, sign=sign, **kwargs)


def p16(
    number: int,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Packs integer into wordsize of 16.

    endianness and signedness is done according to context.

    Arguments:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (bool): Signedness of the converted integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The packed number as a byte.
    """
    return pwnlib.util.packing.p16(number, endianness=endianness, sign=sign, **kwargs)


def p8(
    number: int,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Packs integer into wordsize of 8.

    endianness and signedness is done according to context.

    Arguments:
        number (int): Number to convert
        endianness (str): Endianness of the converted integer ("little"/"big")
        sign (bool): Signedness of the converted integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The packed number as a byte.
    """
    return pwnlib.util.packing.p8(number, endianness=endianness, sign=sign, **kwargs)


def u64(
    data: bytes,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Unpacks 64-bit integer from data.

    endianness and signedness is done according to context.

    Arguments:
        data (bytes): Data to unpack from
        endianness (str): Endianness of the integer ("little"/"big")
        sign (bool): Signedness of the integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The unpacked integer.
    """
    return pwnlib.util.packing.u64(data, endianness=endianness, sign=sign, **kwargs)


def u32(
    data: bytes,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Unpacks 32-bit integer from data.

    endianness and signedness is done according to context.

    Arguments:
        data (bytes): Data to unpack from
        endianness (str): Endianness of the integer ("little"/"big")
        sign (bool): Signedness of the integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The unpacked integer.
    """
    return pwnlib.util.packing.u32(data, endianness=endianness, sign=sign, **kwargs)


def u16(
    data: bytes,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Unpacks 16-bit integer from data.

    endianness and signedness is done according to context.

    Arguments:
        data (bytes): Data to unpack from
        endianness (str): Endianness of the integer ("little"/"big")
        sign (bool): Signedness of the integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The unpacked integer.
    """
    return pwnlib.util.packing.u16(data, endianness=endianness, sign=sign, **kwargs)


def u8(
    data: bytes,
    endianness: Literal["little", "big"] = None,
    sign: bool = None,
    **kwargs: Any,
):
    """
    Unpacks 8-bit integer from data.

    endianness and signedness is done according to context.

    Arguments:
        data (bytes): Data to unpack from
        endianness (str): Endianness of the integer ("little"/"big")
        sign (bool): Signedness of the integer (False/True)
        kwargs: Anything that can be passed to context.local

    Returns:
        The unpacked integer.
    """
    return pwnlib.util.packing.u8(data, endianness=endianness, sign=sign, **kwargs)
