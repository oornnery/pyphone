from pydantic_settings import BaseSettings
from pyphone.core.utils import parser_uri_to_str

class User(BaseSettings):
    username: str = '1001'
    password: str = 'secret'
    domain: str = 'example-domain-sip.com'
    port: int = 5060
    display_info: str = 'Ext 1001'
    caller_id: str = '1001'
    user_agent: str = 'pyphone'
    expires: int = 60

    def uri(self) -> str:
        return parser_uri_to_str(username=self.username, address=self.domain, port=self.port)
