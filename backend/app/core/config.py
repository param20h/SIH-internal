from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central runtime configuration, sourced from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "TVA - Threat Variance Authority"
    environment: str = "development"
    api_prefix: str = "/api/v1"

    database_url: str = "postgresql+psycopg://tva:tva@localhost:5432/tva"
    redis_url: str = "redis://localhost:6379/0"

    geolite2_city_db_path: str = "/data/geoip/GeoLite2-City.mmdb"
    geolite2_asn_db_path: str = "/data/geoip/GeoLite2-ASN.mmdb"

    upload_max_bytes: int = 25 * 1024 * 1024
    max_analysis_seconds: int = 10


@lru_cache
def get_settings() -> Settings:
    return Settings()
