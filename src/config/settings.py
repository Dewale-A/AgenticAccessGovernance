"""Configuration settings for AgenticAccessGovernance"""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # OpenAI Configuration
    openai_api_key: str
    openai_model: str = "gpt-4"
    
    # Database Configuration
    database_url: str = "sqlite:///./agentic_iam.db"
    
    # API Configuration
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_debug: bool = False
    
    # Security
    secret_key: str
    
    # Logging
    log_level: str = "INFO"
    log_file: str = "logs/app.log"
    
    # Financial Services Compliance
    regulator_validation: bool = True
    audit_level: str = "STRICT"
    emergency_access_enabled: bool = True
    
    # Risk Scoring Thresholds
    low_risk_threshold: int = 30
    high_risk_threshold: int = 70
    
    # Certification Requirements (days)
    privacy_training_valid_days: int = 365
    model_risk_training_valid_days: int = 365
    background_check_valid_days: int = 365
    sox_certification_valid_days: int = 365
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()