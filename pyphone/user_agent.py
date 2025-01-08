from dataclasses import dataclass, field
from pyphone.connection import ConnectionConfig
from pyphone.header import Uri

@dataclass
class UserAgentConfig:
    username: str
    server: str
    port: int = field(default=5060)
    login: str = field(default=None)
    password: str = field(default=None)
    realm: str = field(default=None)
    proxy: str = field(default=None)
    user_agent: str = field(default="PyPhone")
    time_out: int = field(default=30)
    expires: int = field(default=30)
    conn_cfg: ConnectionConfig = field(default_factory=ConnectionConfig)

    def uri(self) -> Uri:
        return Uri(user=self.username, host=self.server, port=self.port)
