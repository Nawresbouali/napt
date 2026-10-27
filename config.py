from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "N.A.P.T API"
    database_url: str
    jwt_secret: str
    jwt_expire_minutes: int = 1440
    frontend_url: str = "http://localhost:5000"
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    openrouter_api_key: str = ""
    openrouter_model: str = "google/gemma-4-26b-a4b-it:free"

    class Config:
        env_file = ".env"

settings = Settings()
