import os
from typing import Dict, Any

class ETLConfig:
    # Database configuration
    DATABASE_HOST = os.getenv("DB_HOST", "localhost")
    DATABASE_PORT = os.getenv("DB_PORT", "5432")
    DATABASE_NAME = os.getenv("DB_NAME", "vulnerability_db")
    DATABASE_USER = os.getenv("DB_USER", "postgres")
    DATABASE_PASSWORD = os.getenv("DB_PASSWORD", "password")
    
    @classmethod
    def get_database_url(cls) -> str:
        return f"postgresql://{cls.DATABASE_USER}:{cls.DATABASE_PASSWORD}@{cls.DATABASE_HOST}:{cls.DATABASE_PORT}/{cls.DATABASE_NAME}"
    
    # File processing configuration
    NESSUS_INPUT_DIRECTORY = os.getenv("NESSUS_INPUT_DIR", "data/nessus_reports")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    @classmethod
    def get_logging_config(cls) -> Dict[str, Any]:
        return {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "standard": {
                    "format": cls.LOG_FORMAT
                },
            },
            "handlers": {
                "default": {
                    "level": cls.LOG_LEVEL,
                    "formatter": "standard",
                    "class": "logging.StreamHandler",
                },
                "file": {
                    "level": cls.LOG_LEVEL,
                    "formatter": "standard",
                    "class": "logging.FileHandler",
                    "filename": "logs/etl.log",
                    "mode": "a",
                },
            },
            "loggers": {
                "": {
                    "handlers": ["default", "file"],
                    "level": cls.LOG_LEVEL,
                    "propagate": False
                }
            }
        }
