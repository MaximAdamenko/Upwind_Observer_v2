from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    API_KEY: str = "change-me"
    CLAUDE_API_KEY: str = ""
    CLAUDE_MODEL: str = "claude-sonnet-4-6"
    VIRUS_TOTAL_KEY: str = ""
    MONGODB_URI: str = "mongodb://localhost:27017"
    MONGODB_DB: str = "upwind_observer"


settings = Settings()
