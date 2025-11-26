# config/settings.py
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # API keys
    OPENAI_API_KEY: Optional[str] = Field("", env="OPENAI_API_KEY")
    VIRUSTOTAL_API_KEY: Optional[str] = Field("", env="VT_API_KEY")
    #HIBP_API_KEY: Optional[str] = Field(None, env="HIBP_API_KEY")

    # Optional local common password file
    COMMON_PASSWORDS_FILE: Optional[str] = Field(None, env="COMMON_PASSWORDS_FILE")

    # Webhooks & responders
    N8N_WEBHOOK_URL: Optional[str] = Field(None, env="N8N_WEBHOOK_URL")
    SLACK_WEBHOOK_URL: Optional[str] = Field(None, env="SLACK_WEBHOOK_URL")

    # SMTP (optional)
    SMTP_HOST: Optional[str] = Field(None, env="SMTP_HOST")
    SMTP_PORT: Optional[int] = Field(587, env="SMTP_PORT")
    SMTP_USER: Optional[str] = Field(None, env="SMTP_USER")
    SMTP_PASS: Optional[str] = Field(None, env="SMTP_PASS")
    EMAIL_FROM: Optional[str] = Field(None, env="EMAIL_FROM")
    ALERT_EMAIL_TO: Optional[str] = Field(None, env="ALERT_EMAIL_TO")

    # Database & memory
    DATABASE_URL: str = Field("sqlite:///./events.db", env="DATABASE_URL")
    MEMORY_PATH: str = Field("./memory_store.json", env="MEMORY_PATH")

    # Runtime
    ENVIRONMENT: str = Field("development", env="ENVIRONMENT")
    LOG_LEVEL: str = Field("info", env="LOG_LEVEL")

    # Server
    HOST: str = Field("0.0.0.0", env="HOST")
    PORT: int = Field(8000, env="PORT")

    # Pydantic v2 model config
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        # allow extra env vars (development convenience)
        "extra": "allow",
        # make env lookup case-insensitive
        "case_sensitive": False,
    }

    def __repr__(self) -> str:
        # mask secrets in debug prints
        def mask(v):
            if not v:
                return "<empty>"
            s = str(v)
            if len(s) <= 8:
                return "*" * len(s)
            return s[:4] + ("*" * (len(s) - 8)) + s[-4:]
        return (
            f"Settings(OPENAI_API_KEY={mask(self.OPENAI_API_KEY)}, VIRUSTOTAL_API_KEY={mask(self.VIRUSTOTAL_API_KEY)}, "
            f"N8N_WEBHOOK_URL={self.N8N_WEBHOOK_URL}, DATABASE_URL={self.DATABASE_URL})"
        )

# instantiate global settings
settings = Settings()
# handy startup log (printed when settings loaded/imported)
print("[settings] loaded:", settings)
