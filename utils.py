from typing import Any, Union

from pydantic import BaseModel


class WSMessage(BaseModel):
    type: str
    data: Union[str, dict]

    @classmethod
    def status(cls, message: str) -> "WSMessage":
        return cls(type="status", data=message)

    @classmethod
    def object_message(cls, obj: Any) -> "WSMessage":
        return cls(type="object", data=obj)
