from argparse import ArgumentParser

from pwn import ELF

from ..gadget import pprint_gadgets


def main():
    parser = ArgumentParser(description="Search gadgets in binary")
    parser.add_argument(
        "--force", "-f", action="store_true", help="Force search gadgets"
    )
    parser.add_argument(
        "--prefix",
        "-p",
        help="The prefix to use for the variables",
        action="store",
    )
    parser.add_argument(
        "--regs",
        "-r",
        help="The registers to use for the variables",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--insts",
        "-i",
        help="The instructions together with a `ret`",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--strs",
        "-s",
        help="The strings to search for",
        action="append",
        default=[],
    )
    parser.add_argument("file", help="The binary file to search gadgets in")
    args = parser.parse_args()
    args.file = ELF(args.file, checksec=False)
    args.prefix = (
        args.prefix
        if args.prefix
        else ("elf.address" if args.file.elftype == "EXEC" else "libc.address")
    )
    pprint_gadgets(**vars(args))
