<div align="center">


# PwNo

_✨ Pwntools Extensions that Just Works! ✨_	

<p>
<a href="./LICENSE">
    <img src="https://img.shields.io/github/license/MuelNova/PwNo.svg" alt="license">
</a>
</p>
<a href="https://pypi.python.org/pypi/PwNo">
    <img src="https://img.shields.io/pypi/v/PwNo.svg" alt="pypi">
</a>
<img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="python">

<p>
<img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/MuelNova/PwNo?logo=github&style=for-the-badge">
</p>

</div>

快速拓展你的 [pwntools](https://github.com/Gallopsled/pwntools)，使其更加易用，针对 pwn 开发

## Features

- [x] 开箱即用
- [x] 完整的类型注解
- [x] 好用简单的小工具
- [ ] And more...

## TL;DR

### 一键缩写

see [context](#context)

```python
from pwn import *
from pwno import *

p = process(['/path/to/your/elf'])

sl(b'cat /flag')
ia()  # 无需设置！
```

### And More ...



## Installation

<details>
<summary>使用 pip 安装</summary>
欸，还没部署呢
</details>


<details>
<summary>本地安装</summary>

    git clone https://github.com/MuelNova/PwNo
    cd PwNo
    pip install -e .
</details>

## Usage

只需在你的 exp.py 导入

```python
from pwno import *
```



## Docs

### context

PwNo 为脚本实现了缩写功能以加速你的脚本编写，而你不需要做任何操作
> 默认的导出：
>
> ​        >>> send  = process.send
> ​        >>> sl = process.sendline
> ​        >>> sa = process.sendafter
> ​        >>> sla = process.sendlineafter
>
> ​        >>> recv = process.recv
> ​        >>> recvu = process.recvuntil
> ​        >>> recvn = process.recvn
> ​        >>> recvl = process.recvline
>
> ​        >>> ia = process.interactive

```python
from pwn import *
from pwno import *

p = process(['/path/to/your/elf'])

sl(b'cat /flag')  # equals to p.sendline(b'cat /flag')
ia()  # equals to p.interactive()
```

这对变量名没有任何要求

```python
from pwn import *
from pwno import *

I_Hate_PWN = remote('weird.challenge.pwn', 11451)

sl(b'cat /flag')  # equals to I_Hate_PWN.sendline(b'cat /flag')
ia()  # equals to I_Hate_PWN.interactive()
```

同时也支持循环操作，甚至修改变量名！在原来的 process 不可用的情况下，PwNo 会重新找到最新创建的 process/remote

```python
from pwn import *
from pwno import *

p = process(['/path/to/your/elf'])
# I hate the name 'p'
while True:
    sh = process(['/path/to/your/elf'])

    sl('I like sh!')  # equals to sh.sendline('I like sh!')
    sh.close()
```

#### abbr

不喜欢 PwNo 设置的缩写？Make your owns!

PwNo 导出了方法 `abbr`，使用它，你可以轻松的设置你自己的缩写，或是设置全局的缩写

```python
from pwn import *
from pwno import *

p = process(['/path/to/your/elf'])
sh = process(['/path/to/your/elf'])

new_sl = abbr(process.sendline)  # Global Abbreviation
new_sl(b'sh')  # equals to sh.sendline(b'sh')


my_sl = abbr(p.sendline)
my_sl(b'OH~~~')  # equals to p.sendline(b'OH~~~')
new_sl(b'sh')  # equals to sh.sendline(b'sh')

sh.close()
new_sl(b'p')  # equals to p.sendline(b'p')
```



### typing

#### pack

PwNo 为常用的包装与解包函数添加了类型注解，现在你终于不需要对着标红的 `p64` \ `u32` 眉头紧皱了！

![TypeHint](docs/img/1.png)



### helper

PwNo 提供了省时省力的小工具加快你的解题。

#### uu64 / uu32

泄露地址仍然使用 `u64(recv(6).ljust(8, b'\x00'))`？为什么不试试

```python
uu64(recv(6))
```



## Editing...
