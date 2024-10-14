from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict( 
        env_file='.env', env_file_encoding='utf-8'
    )
    SECRET_KEY: str
    SIP_USERNAME: str
    SIP_PASSWORD: str
    SIP_DOMAIN: str
    SIP_DESTINATION: str