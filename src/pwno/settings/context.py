from pydantic import BaseModel, field_validator

class ContextSettings(BaseModel):

    # context.terminal
    terminal: list[str] = ""
    log_level: str = "debug"
    os: str = "linux"

    @field_validator("terminal", mode="before")
    def validate_terminal(cls, v):
        if isinstance(v, str):
            return v.split(" ")
        return v
    