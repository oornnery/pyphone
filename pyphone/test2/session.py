from dataclasses import dataclass, field

from pyphone.utils import SIPTransportType


@dataclass
class SessionConfig:
    local_ip: str = field(default='0.0.0.0')
    local_port: str = field(default='10060')
    public_ip: str = field(default='0.0.0.0')
    public_port: str = field(default='0')
    protocol: SIPTransportType = field(default=SIPTransportType.UDP)
    sip_domain: str
    sip_port: str
    sip_username: str
    sip_password: str = None
    
    def via_uri(self):
        return f'{self.local_ip}:{self.local_port}'

    def from_uri(self):
        _port = (f':{self.sip_port}' if self.sip_port else '')
        return f'{self.sip_username}@{self.sip_domain}{_port}'
    
