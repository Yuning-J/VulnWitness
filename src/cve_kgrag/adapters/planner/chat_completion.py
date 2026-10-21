"""The part of an OpenAI-compatible chat completion the planner reads: the first choice's
message content. Every other field, ``reasoning_content`` included, is ignored."""

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ChatMessage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore", hide_input_in_errors=True)

    content: str

    @field_validator("content")
    @classmethod
    def check_content(cls, content: str) -> str:
        # DeepSeek's JSON mode documents that it may answer with empty content.
        if not content.strip():
            raise ValueError("the message has no content")
        return content


class ChatChoice(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore", hide_input_in_errors=True)

    message: ChatMessage


class ChatCompletion(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore", hide_input_in_errors=True)

    choices: tuple[ChatChoice, ...] = Field(min_length=1)
