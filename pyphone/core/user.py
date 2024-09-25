from dataclasses import dataclass
from pyphone.core.message import Uri


@dataclass
class User:
    username: str
    domain: str
    
    def uri(self) -> Uri:
        return Uri(user=self.username, address=self.domain)
        