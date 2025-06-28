from typing import Any


class Deprecated:
    def __init__(
        self,
        instance: Any,
        varname: str,
        replacement: str | None = None,
        msg: str | None = None,
    ):
        self._varname = varname
        self._instance = instance
        self._replacement = replacement
        self._msg = msg
        self._warning_shown = False

    def __getattr__(self, name):
        if not self._warning_shown:
            print(
                "\033[1m\033[93m[!] Warning:\033[0m \033[1m",
                self._construct_msg(),
                "\033[0m",
                sep="",
            )
            self._warning_shown = True
        return getattr(self._instance, name)

    def _construct_msg(self):
        if self._msg is None:
            msg = f"'{self._varname}' is deprecated and will be removed shortly."
            if self._replacement is not None:
                msg += f" Use '{self._replacement}' instead."
            return msg
        return self._msg.format(varname=self._varname, replacement=self._replacement)
