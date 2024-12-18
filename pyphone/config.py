from dataclass import dataclass, field
from typing import Tuple, Optional
from .utils import TransportProtocol, DTMFMode


@dataclass
class SIPConfig:
    local_ip: str = field(default='0.0.0.0')
    local_port: int = field(default=10060)
    remote_ip: str = field(default='0.0.0.0')
    remote_port: int = field(default=5060)
    transport: TransportProtocol = field(default=TransportProtocol.UDP)
    use_tls: bool = field(default=False)
    keep_alive_interval: int = field(default=30)
    timeout: int = field(default=5)
    max_retries: int = field(default=3)
    dtmf_mode: DTMFMode = field(default=DTMFMode.RFC2833)
    rtp_port_range: Tuple[int, int] = field(default=(10000, 20000))
    tls_cert: Optional[str] = field(default=None)
    tls_key: Optional[str] = field(default=None)
    registration_expires: int = field(default=60)
    user_agent: str = field(default='PyPhone')
