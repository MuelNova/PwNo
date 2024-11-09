import os
import toml

from pathlib import Path
from typing import Tuple, Type

from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
    PydanticBaseSettingsSource,
    TomlConfigSettingsSource
)
from .general import GeneralSettings
from .context import ContextSettings
# 配置文件路径
_DEFAULT_CONFIG_PATH = Path.home() / ".config" / "pwno" / "config.toml"

CONFIG_FILE = os.environ.get("PWNO_CONFIG_PATH") or _DEFAULT_CONFIG_PATH

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        extra="ignore",
        toml_file=CONFIG_FILE
    )

    general: GeneralSettings = GeneralSettings()
    context: ContextSettings = ContextSettings()

    def __del__(self):
        if self.model_config["toml_file"] != _DEFAULT_CONFIG_PATH:
            return
        try:
            if not Path(_DEFAULT_CONFIG_PATH).parent.exists():
                Path(_DEFAULT_CONFIG_PATH).parent.mkdir(parents=True, exist_ok=True)
            with Path(_DEFAULT_CONFIG_PATH).open("w") as file:
                toml.dump(self.model_dump(), file)
        except Exception as e:
            print(f"保存配置文件时发生错误: {e}")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        return (TomlConfigSettingsSource(settings_cls), env_settings, init_settings)

settings = Settings()

print(settings)
