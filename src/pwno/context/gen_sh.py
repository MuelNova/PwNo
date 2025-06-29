import os

from typing import TYPE_CHECKING, overload
from pathlib import Path
from pwn import gdb, process, remote, context

from ..helper.utils import DBG_CNT
from ..context import Config
from ..settings import settings

# Ensure DBG_CNT is defined if not imported correctly
try:
    DBG_CNT  # type: ignore
except NameError:
    DBG_CNT = 0

if TYPE_CHECKING:
    config: Config


class SHWrapper:
    def __init__(self, target: process | remote):
        object.__setattr__(self, "target", target)

    def __enter__(self):
        return self.target

    def __exit__(self, exc_type, exc_value, traceback):
        if hasattr(self.target, "close"):
            self.target.close()
        return False

    def __getattr__(self, name):
        return getattr(self.target, name)

    def __setattr__(self, name, value):
        if name == "target":
            object.__setattr__(self, name, value)
        else:
            setattr(self.target, name, value)

    def __getattribute__(self, name):
        # 对于特殊属性，返回目标对象的值
        if name in ("__class__", "__module__", "__dict__"):
            target = object.__getattribute__(self, "target")
            return getattr(target, name)
        elif name == "target":
            return object.__getattribute__(self, name)
        else:
            try:
                return object.__getattribute__(self, name)
            except AttributeError:
                target = object.__getattribute__(self, "target")
                return getattr(target, name)

    def __eq__(self, other):
        """比较时使用目标对象"""
        if hasattr(other, "target"):
            return self.target == other.target
        return self.target == other

    def __ne__(self, other):
        """不等比较时使用目标对象"""
        return not self.__eq__(other)

    def __hash__(self):
        """哈希时使用目标对象"""
        return hash(self.target)

    def __repr__(self):
        """字符串表示时使用目标对象"""
        return repr(self.target)

    def __str__(self):
        """字符串转换时使用目标对象"""
        return str(self.target)

    def __bool__(self):
        """布尔值转换时使用目标对象"""
        return bool(self.target)

    def __len__(self):
        """长度检查时使用目标对象"""
        return len(self.target)

    def __iter__(self):
        """迭代时使用目标对象"""
        return iter(self.target)

    def __contains__(self, item):
        """包含检查时使用目标对象"""
        return item in self.target


@overload
def gen_sh() -> process | remote:
    """生成一个 process 或 remote 实例，使用命令行参数或默认配置。"""
    ...


@overload
def gen_sh(f: str | Path | list[str]) -> process:
    """生成一个 process 实例，使用指定的文件作为附件。"""
    ...


@overload
def gen_sh(f_or_host: str | Path) -> process | remote:
    """
    生成一个 process 或 remote 实例，使用指定的文件或主机地址。
    如果传入的参数是一个字符串或 Path，则作为 config.ATTACHMENT。
    如果检测到格式为 "host:port"，则作为 config.HOST 和 config.PORT。
    """
    ...


@overload
def gen_sh(host: str | Path, port: int) -> remote:
    """
    生成一个 remote 实例，使用指定的主机地址和端口。
    如果传入的参数是两个，则第一个参数作为 config.HOST，第二个参数作为 config.PORT。
    """
    ...


def __gen_sh(*args, **kwargs) -> process | remote:  # noqa: C901
    """
    生成一个 process 或 remote 实例，支持多种调用方式：

    1. gen_sh() -> 使用命令行参数或默认配置
    2. gen_sh(f) -> 使用指定文件创建 process
    3. gen_sh(f_or_host) -> 根据参数类型创建 process 或 remote
    4. gen_sh(host, port) -> 使用指定主机和端口创建 remote
    """
    if len(args) == 0:
        # 情况1: gen_sh() - 使用默认配置或命令行参数
        pass
    elif len(args) == 1:
        # 情况2和3: gen_sh(f) 或 gen_sh(f_or_host)
        arg = args[0]
        if isinstance(arg, list):
            if len(arg) > 1:
                config.RUNARGS = " ".join(arg[1:])
            arg = arg[0]
        arg_str = str(arg)
        if ":" in arg_str:
            parts = arg_str.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                config.HOST = parts[0]
                config.PORT = int(parts[1])
                config.REMOTE = True
            else:
                config.ATTACHMENT = arg_str
        else:
            config.ATTACHMENT = arg_str

    elif len(args) == 2:
        # 情况4: gen_sh(host, port)
        host, port = args
        config.HOST = str(host)
        config.PORT = int(port)
        config.REMOTE = True

    else:
        raise ValueError(f"gen_sh() 接受 0-2 个位置参数，但给出了 {len(args)} 个")

    if config.REMOTE:
        return remote(config.HOST, config.PORT)

    if config.ATTACHMENT:
        attachment = config.ATTACHMENT
        if not attachment.startswith(".") and not attachment.startswith("/"):
            config.ATTACHMENT = "./" + attachment

        if config.GDB:
            gdb_script = config.GDB_SCRIPT or get_dbg_args()
            return gdb.debug(
                [config.ATTACHMENT, *config.RUNARGS.split(" ")],
                gdbscript=gdb_script,
            )

        return process([config.ATTACHMENT, *config.RUNARGS.split(" ")], **kwargs)

    raise ValueError()


def gen_sh(*args, **kwargs) -> process | remote:
    """
    生成一个 process 或 remote 实例，支持多种调用方式：

    1. gen_sh() -> 使用命令行参数或默认配置
    2. gen_sh(f) -> 使用指定文件创建 process
    3. gen_sh(f_or_host) -> 根据参数类型创建 process 或 remote
    4. gen_sh(host, port) -> 使用指定主机和端口创建 remote

    返回值:
        返回一个 process 或 remote 实例。
    """
    return SHWrapper(__gen_sh(*args, **kwargs))  # type: ignore


def get_dbg_args() -> str:  # noqa: C901
    import inspect

    frame = inspect.currentframe()
    while frame and frame.f_locals.get("__name__", None) != "__main__":
        frame = frame.f_back

    if not frame:
        return ""

    filename = frame.f_code.co_filename
    with open(filename) as f:
        src = f.read()

    import ast

    tree = ast.parse(src)

    class FindDbg(ast.NodeVisitor):
        def __init__(self):
            self.dbg: list[str] = []

        def visit_Call(self, node):
            if isinstance(node.func, ast.Name) and node.func.id == "dbg":
                global DBG_CNT
                if node.args:
                    DBG_CNT += 1
                    if config.DBG and DBG_CNT in config.DBG:
                        expr = node.args[0]
                        if isinstance(expr, ast.Constant):
                            self.dbg.append(str(expr.value))
                if node.keywords:
                    for kw in node.keywords:
                        if kw.arg == "gdb_script":
                            DBG_CNT += 1
                            if (
                                config.DBG
                                and DBG_CNT in config.DBG
                                and isinstance(kw.value, ast.Constant)
                            ):
                                self.dbg.append(str(kw.value.value))
            self.generic_visit(node)

    find_dbg = FindDbg()
    find_dbg.visit(tree)

    return "\n".join(find_dbg.dbg)


def set_terminal():
    if settings.context.terminal:
        context.terminal = settings.context.terminal
        return

    # if we're using wsl, set context terminal to cmd.exe
    if "WSL_DISTRO_NAME" in os.environ:
        args = ["cmd.exe", "/c", "start"]
        # if "WT_SESSION" in os.environ:
        args.extend(["wt.exe", "-w", "0"])

        if distro_name := os.getenv("WSL_DISTRO_NAME"):
            args.extend(["wsl.exe", "-d", distro_name, "bash", "-c"])
        else:
            args.extend(["bash.exe", "-c"])

        context.terminal = args


def remove_wsl_path():
    original_path = os.environ.get("PATH", "")
    path_components = original_path.split(os.pathsep)

    # Filter out paths starting with '/mnt/'
    filtered_components = set([p for p in path_components if not p.startswith("/mnt/")])

    # Join the remaining components and update PATH
    new_path = os.pathsep.join(sorted(filtered_components, key=len))
    os.environ["PATH"] = new_path


def initialization():
    context.log_level = settings.context.log_level
    context.os = settings.context.os
    set_terminal()
    if "WSL_DISTRO_NAME" in os.environ:
        remove_wsl_path()


initialization()
