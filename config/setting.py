# config/settings.py
from pydantic import BaseSettings

class Settings(BaseSettings):
    OPENAI_API_KEY: str
    VIRUSTOTAL_API_KEY: str
    HIBP_API_KEY: str | None = None
    N8N_WEBHOOK_URL: str
    DATABASE_URL: str = "sqlite:///./events.db"
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
