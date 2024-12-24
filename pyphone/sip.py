from abc import ABC, abstractmethod
from pydantic import BaseModel
from pyphone.auth import AuthConfig
from pyphone.transport import TransportConfig
from pyphone.session import SessionConfig

class SIPConfig(BaseModel):
    session_cfg: SessionConfig
    transport_cfg: TransportConfig
    auth_cfg: AuthConfig


class SIP(ABC):
    @abstractmethod
    def register(self):
        pass

    @abstractmethod
    def invite(self):
        pass

    @abstractmethod
    def ack(self):
        pass

    @abstractmethod
    def bye(self):
        pass
    
    @abstractmethod
    def cancel(self):
        pass
    
    @abstractmethod
    def options(self):
        pass
    
    @abstractmethod
    def info(self):
        pass
    
    @abstractmethod
    def send_message(self):
        pass
    
    @abstractmethod
    def receive_message(self):
        pass
    
