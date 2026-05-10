from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    API_KEY: str = "change-me"
    CLAUDE_API_KEY: str = ""
    CLAUDE_MODEL: str = "claude-sonnet-4-6"
    VIRUS_TOTAL_KEY: str = ""
    DATABASE_URL: str = "sqlite:///./upwind.db"


settings = Settings()
