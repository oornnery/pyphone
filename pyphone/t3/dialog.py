from __future__ import annotations

from datetime import datetime
from enum import Enum, auto
from typing import List, Callable, Union

from pyphone.message import Request, Response, SIPMessage
from pyphone.utils import StatusCode, Method
from pyphone.logger import logger


class DialogError(Exception):
    pass

class DialogState(Enum):
    INIT = auto()
    PROGRESS = auto()
    CONFIRMED = auto()
    TERMINATED = auto()


class Dialog:
    def __init__(
            self,
            on_message_created: Request,
            callback: Callable,
            state: DialogState = DialogState.INIT,
        ):
            self._on_message_created = on_message_created
            self.state = state
            self.callback = callback
            self._messages: List[Union[Request, Response]] = []
            # properties
            self._local_seq: int = None
            self._created_at: datetime = None
            self._updated_at: datetime = None
            # TODO: implement timeout and max retransmission
    @property
    def call_id(self) -> str:
        return self._on_message_created.headers['Call-ID']
    
    @property
    def local_tag(self) -> str:
        return self._on_message_created.headers['From'].tag
    
    @property
    def remote_tag(self) -> str:
        return self._on_message_created.headers['To'].tag

    @property
    def local_seq(self) -> int:
        if self._local_seq is None:
            self._local_seq = 1
        return self._local_seq
    
    @local_seq.setter
    def local_seq(self, value: int) -> None:
        self._local_seq = value
    
    @property
    def remote_seq(self) -> int:
        return self._messages[-1].headers['CSeq'].seq
    
    @property
    def local_target(self) -> str:
        return self._on_message_created.headers['From'].address.host
    
    @property
    def remote_target(self) -> str:
        return self._on_message_created.headers['Via'].host
    
    @property
    def created_at(self) -> datetime:
        if self._created_at is None:
            self._created_at = datetime.now()
        return self._created_at
    
    @property
    def updated_at(self) -> datetime:
        if self._updated_at is None:
            self._updated_at = self._time_now()
        return self._updated_at
    
    @updated_at.setter
    def updated_at(self, value: datetime) -> None:
        self._updated_at = value
    
    @staticmethod
    def _time_now() -> datetime:
        return datetime.now()

    def __iadd__(self, message: Union[Request, Response]) -> None:
        # TODO: Refactor this method
        logger.info(f'Adding message to dialog: {message}')
        if not isinstance(message, SIPMessage):
            raise DialogError(f'Failed to add message to dialog: {message} is not a SIPMessage')
        logger.info(str(message))
        # Add message to dialog list and update timestamp
        self._messages.append(message)
        self.updated_at = datetime.now()
    
    def _update_state_by_request(self, message: Request) -> None:
        try:
            match message.method:
                case Method.INVITE:
                    self.state = DialogState.PROGRESS
                    self.handle_progess(message)
                case Method.ACK:
                    self.state = DialogState.CONFIRMED
                    self.handle_confirmed(message)
                case Method.BYE | Method.CANCEL:
                    self.state = DialogState.TERMINATED
                    self.handle_terminated(message)
                case _:
                    raise DialogError(f'Failed to add message to dialog: {message} is not a valid method')
        except Exception as e:
            logger.error(f'Failed to add message to dialog: {e}')
            self.state = DialogState.TERMINATED
            self.handle_terminated(message)
        finally:
            logger.info(f'Updated dialog state to {self.state}')
            return None

    def _update_state_by_response(self, message: Response) -> None:
        try:
            match message.status_code:
                case StatusCode.TRYING | StatusCode.RINGING | StatusCode.SESSION_PROGRESS:
                    self.state = DialogState.PROGRESS
                case StatusCode.OK:
                    self.state = DialogState.CONFIRMED
                case StatusCode.BUSY_HERE |\
                    StatusCode.CANCEL |\
                    StatusCode.REQUEST_TERMINATED|\
                    StatusCode.REQUEST_TIMEOUT |\
                    StatusCode.NOT_FOUND |\
                    StatusCode.SERVER_INTERNAL_ERROR |\
                    StatusCode.TEMPORARILY_UNAVAILABLE |\
                    StatusCode.CALL_TRANSACTION_DOES_NOT_EXIST |\
                    StatusCode.DECLINE:
                    self.state = DialogState.TERMINATED
                case _:
                    raise DialogError(f'Failed to add message to dialog: {message} is not a valid status code')
        except Exception as e:
            logger.error(f'Failed to add message to dialog: {e}')
            self.state = DialogState.TERMINATED
        finally:
            logger.info(f'Updated dialog state to {self.state}')
            return None
    
    def append(self, message: SIPMessage): 
        self += message
        return self
    
    def __repr__(self) -> str:
        return f"Dialog(call_id={self.call_id}, state={self.state})"
