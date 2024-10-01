from pydantic_settings import BaseSettings

try:
    from dialog.header import Uri
except ImportError:
    from pyphone.core.header import Uri


class User(BaseSettings):
    username: str = '1001'
    password: str = 'secret'
    domain: str = 'example-domain-sip.com'
    port: int = 5060
    display_info: str = 'Ext 1001'
    caller_id: str = '1001'
    user_agent: str = 'pyphone'
    register_expires: int = 60

    @property
    def uri(self) -> Uri:
        return Uri(user=self.username, address=self.domain)
