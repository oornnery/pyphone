from pydantic import BaseModel


class AuthConfig(BaseModel):
    username: str
    password: str
    user_agent: str
    realm: str
    proxy: str
    expires: int