from typing import Generic, TypeVar, Any

T = TypeVar("T")


class Export(Generic[T]):
    """
    一个通用的导出类，用于导出初始化为 None 的全局变量。
    """

    def __init__(self):
        """
        初始化Export对象，设置内部实例为None。
        """
        setattr(self, "_Export__instance", None)

    def __getattr__(self, name: str) -> Any:
        """
        获取属性时，实际上是从内部实例中获取。
        """
        return getattr(self.__instance, name)

    def __setattr__(self, name: str, value: Any):
        """
        设置属性时，如果是设置内部实例，则直接设置；否则，设置内部实例的属性。
        """
        if name == "_Export__instance":
            object.__setattr__(self, name, value)
        else:
            setattr(self.__instance, name, value) 
    
    def __repr__(self) -> str:
        """
        返回内部实例的字符串表示。
        """
        return self.__instance.__repr__()

    def __str__(self) -> str:
        """
        返回内部实例的字符串表示。
        """
        return self.__instance.__str__()

    @property
    def __class__(self) -> type[T]:
        """
        返回内部实例的类。
        """
        return self.__instance.__class__

def set_export(instance: Export[T], value: T):
    if not isinstance(instance, Export):
        raise TypeError("instance must be an instance of Export")
    setattr(instance, "_Export__instance", value)
