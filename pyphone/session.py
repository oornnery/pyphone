from abc import ABC, abstractmethod
from pydantic import BaseModel


class SessionConfig(BaseModel):
    sip_server: str
    sip_port: int
    time_out: int


class Session(ABC):
    @abstractmethod
    def start(self):
        pass
    
    @abstractmethod
    def stop(self):
        pass
    
    @abstractmethod
    def _start_keep_alive(self):
        pass
    
    @abstractmethod
    def _stop_keep_alive(self):
        pass
    
    @abstractmethod
    def _handle_message(self):
        pass