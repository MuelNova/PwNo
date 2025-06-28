import pickle
from itertools import chain
from pathlib import Path

from pwn import ELF
from ropper import Gadget, RopperService

from ..settings import settings
from ..typing import ELFType


def load_gadgets(file: ELFType, force=None, **kwargs) -> RopperService:
    """
    查找 file 的 gadgets，如果 file 是 DYN 类型的 ELF，则会缓存 gadgets

    Args:
        file (ELFType): 要查找 gadgets 的 ELF 文件
        force (bool, optional): 是否不使用缓存查找 gadgets. Defaults to None.

    Returns:
        RopperService: RopperService 实例
    """
    if isinstance(file, (str, Path)):
        file = ELF(file, checksec=False)
    cache = file.elftype == "DYN"

    options = {
        "color": False,
        "badbytes": "",
        "all": False,
        "inst_count": 6,
        "type": "all",
        "detailed": False,
    }
    options.update(kwargs)

    if cache:
        cache_file = Path(settings.general.CACHE_DIR) / (
            file.buildid.hex() if file.buildid else file.path
        )
        if not cache_file.exists() or force:
            rs = RopperService(options)
            rs.addFile(file.path)
            rs.loadGadgetsFor()
            gadgets = rs.getFileFor(file.path)
            if gadgets is None:
                raise ValueError(f"Failed to load gadgets for {file.path}")
            pickle.dump(gadgets.gadgets, cache_file.open("wb"))
        else:
            rs = RopperService(options)
            rs.addFile(file.path)
            rs.files[0].gadgets = pickle.load(cache_file.open("rb"))
            rs.files[0].analyzed = True

    else:
        rs = RopperService(options)
        rs.addFile(file.path)
        rs.loadGadgetsFor()

    return rs


def pprint_gadgets(
    file: ELFType,
    force: bool = False,
    prefix: str = "libc.address",
    regs: list[str] = [],
    insts: list[str] = [],
    strs: list[str] = [],
    **kwargs,
) -> None:
    """
    打印 file 的 gadgets, 以及 strings。返回可在 exp 中使用的常量

    Args:
        file (ELFType): 要查找 gadgets 的 ELF 文件
        force (bool, optional): 是否不使用缓存查找 gadgets. Defaults to False.
        prefix (str, optional): 变量的前缀. Defaults to "libc.address".
        regs (list[str], optional): 寄存器列表. Defaults to [].
        insts (list[str], optional): 指令列表. Defaults to [].
        strs (list[str], optional): 字符串列表. Defaults to [].

    Returns:
        None
    """
    rs = load_gadgets(file, force=force, **kwargs)
    if not regs and not insts and not strs:
        regs = ["rdi", "rsi", "rdx", "rax"]
        insts = [
            "syscall",
        ]
        strs = ["/bin/sh"]

    queries = list()
    if regs:
        queries += (f"pop {reg}; ret;" for reg in regs)
    if insts:
        queries += (f"{inst}; ret;" for inst in insts)
    queries = "|".join(chain(queries))

    def gadget_to_var(gadget: str):
        return gadget.replace(";", "").strip().replace(" ", "_")

    def string_to_var(string: str):
        return string.replace("/", "").replace(".", "").replace("-", "")

    gadgets = []
    strings = []

    if queries:
        gadgets = rs.search(queries)
        for g in gadgets:
            gadget: Gadget = g[1]
            print(
                f"{gadget_to_var(gadget.simpleInstructionString())} = "
                f"{prefix + ' + ' if prefix else ''}"
                f"{gadget.address:#x}  # {gadget._gadget}"
            )

    if strs:
        strdict = rs.searchString("|".join(strs))
        strings: list[tuple[int, bytes]] = next(iter(strdict.values()), [])
    for address, string in strings:
        print(
            f"{string_to_var(string.decode())} = {prefix + ' + ' if prefix else ''}"
            f"{address:#x}  # {string.decode()}"
        )
