from pydantic import BaseModel
from pwn import flat

from ...context import context


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
    _unused2: bytes = b""

    def __bytes__(self) -> bytes:
        if context.arch != "amd64":
            raise Exception(f"{self.__class__.__name__} is only supported on amd64")
        return flat(
            {
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
                    self._fileno.to_bytes(4, "little")
                    + self._flags2.to_bytes(4, "little"),
                    self._old_offset,
                    (
                        self._cur_column.to_bytes(2, "little")
                        + self._vtable_offset.to_bytes(1, "little")
                        + self._shortbuf.to_bytes(1, "little")
                    ).ljust(8, b"\x00"),
                    self._lock,
                    self._offset,
                    self._codecvt,
                    self._wide_data,
                    self._freeres_list,
                    self._freeres_buf,
                    self._pad5,
                    self._mode.to_bytes(4, "little"),
                ],
                0xC4: self._unused2.ljust(20, b"\x00"),
            }
        )


class IO_FILE_plus(IO_FILE):
    vtable: int = 0

    def __bytes__(self) -> bytes:
        return flat(super().__bytes__().ljust(0xD8, b"\x00"), self.vtable)
