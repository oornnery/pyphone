from dataclasses import dataclass, field
from pyphone.transport import TransportConfig


@dataclass
class UserAgent:
    username: str = field(default='1001')
    password: str = field(default='password')
    host: str = field(default='example-domain-sip.com')
    port: int = field(default=5060)
    display_name: str = field(default='1001 SIP Phone')
    caller_id: str = field(default='1001')
    user_agent: str = field(default='pyphone')
    expires: int = field(default=0)
    transport: TransportConfig = field(default_factory=TransportConfig)
    
    def uri(self, user: str = None) -> str:
        _port = f':{self.port}' if self.port else ''
        return f'sip:{user or self.username}@{self.host}{_port}'
