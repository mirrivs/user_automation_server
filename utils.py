from pydantic import BaseModel
from typing import Union, Any

class WSMessage(BaseModel):
    type: str
    data: Union[str, dict]

    @classmethod
    def status(cls, message: str) -> "WSMessage":
        return cls(type="status", data=message)

    @classmethod
    def object_message(cls, obj: Any) -> "WSMessage":
        return cls(type="object", data=obj)