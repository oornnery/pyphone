from abc import ABC
from enum import Enum
from pydantic import BaseModel


class SIPRequest(BaseModel):
    method: str
    uri: str
    headers: dict
    body: str


class SIPResponse(BaseModel):
    status: int
    uri: str
    headers: dict
    body: str


class DialogState(Enum):
    INITIAL = "INITIAL"
    PROCEEDING = "PROCEEDING"
    COMPLETED = "COMPLETED"
    CONFIRMED = "CONFIRMED"
    TERMINATED = "TERMINATED"


class SIPDialog(ABC):
    def __init__(
        self,
        call_id: str,
        local_tag: str,
        remote_tag: str,
        local_uri: str,
        remote_uri: str,
        state: DialogState = DialogState.INITIAL,
    ):
        self.call_id = call_id
        self.local_tag = local_tag
        self.remote_tag = remote_tag
        self.local_uri = local_uri
        self.remote_uri = remote_uri
        self.state = state
