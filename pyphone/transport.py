from abc import ABC, abstractmethod
from enum import Enum, auto
from pydantic import BaseModel


class TransportType(Enum):
    UDP = auto()
    TCP = auto()


class TransportConfig(BaseModel):
    transport: TransportType
    local_ip: str
    local_port: int
    sip_server: str
    sip_port: int


class Transport(ABC):
    def __init__(self, config: TransportConfig):
        self.config = config

    @abstractmethod
    def send(self, data: bytes):
        pass

    @abstractmethod
    def recv(self) -> bytes:
        pass

    @abstractmethod
    def close(self):
        pass

    @abstractmethod
    def __enter__(self):
        pass

    @abstractmethod
    def __exit__(self, exc_type, exc_value, traceback):
        pass

    @abstractmethod
    def __del__(self):
        pass