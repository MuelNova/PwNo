from pwno import *

sh = gen_sh()

dbg("b *0x400000")
dbg(gdb_script="b *0x400001")

ia()
