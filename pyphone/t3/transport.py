from dataclasses import dataclass, field
from pyphone.utils import ProtocolType

@dataclass
class TransportConfig:
    protocol: ProtocolType = field(default=ProtocolType.UDP)
    local_address: str = field(default='0.0.0.0')
    local_port: str = field(default='5060')
    public_address: str = field(default='0.0.0.0')
    public_port: str = field(default='5060')
    buffer_size: int = field(default=1024)
