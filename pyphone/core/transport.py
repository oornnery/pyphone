from pydantic_settings import BaseSettings

from pyphone.core.utils import ProtocolType


class Transport(BaseSettings):
    protocol: ProtocolType = ProtocolType.UDP
    local_address: str = '0.0.0.0'
    local_port: str = '5060'
    public_address: str = '0.0.0.0'
    public_port: str = '5060'
    buffer_size: int = 1024

