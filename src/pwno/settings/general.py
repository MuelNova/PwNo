from pydantic import BaseModel, Field, field_validator
from pathlib import Path

class GeneralSettings(BaseModel):
# 默认缓存目录
    CACHE_DIR: str = Field(default=str(Path.home() / ".cache" / "pwno"), description="缓存目录")

    @field_validator("CACHE_DIR", mode="before")
    def _validate_cache_dir(cls, v):
        if not Path(v).exists():
            Path(v).mkdir(parents=True, exist_ok=True)
        return v