from pathlib import Path

from pydantic import BaseModel, Field, field_validator, model_validator
from typing_extensions import Annotated


class Settings(BaseModel):
    CACHE_DIR: Annotated[str, Field(validate_default=True)] = None

    @field_validator("CACHE_DIR", mode="before")
    def _validate_cache_dir(cls, v):
        if v is None:
            v = Path.home() / ".cache" / "pwno"
            return str(v.absolute())
        return v

    @model_validator(mode="after")
    def _validate_model(self):
        if not (v := Path(self.CACHE_DIR)).exists():
            v.mkdir(parents=True)
        return self


settings = Settings()
