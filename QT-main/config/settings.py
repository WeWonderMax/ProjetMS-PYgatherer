"""
Application settings and configuration
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
TEMP_DIR = BASE_DIR / "temp"
LOG_DIR = BASE_DIR / "logs"
EXPORT_DIR = BASE_DIR / "exports"

# Ensure directories exist
for directory in [TEMP_DIR, LOG_DIR, EXPORT_DIR]:
    directory.mkdir(exist_ok=True)

# Path Settings
PATHS = {
    "BASE_DIR": BASE_DIR,
    "TEMP_DIR": TEMP_DIR,
    "LOG_DIR": LOG_DIR,
    "EXPORT_DIR": EXPORT_DIR,
}

# API Keys and Endpoints
API_KEYS = {
    "VIRUSTOTAL": os.getenv("VIRUSTOTAL_API_KEY", ""),
    "ABUSE_IPDB": os.getenv("ABUSEIPDB_API_KEY", ""),
    "SHODAN": os.getenv("SHODAN_API_KEY", ""),
}

# API Endpoints
API_ENDPOINTS = {
    "VIRUSTOTAL": {
        "BASE": "https://www.virustotal.com/api/v3",
        "IP": "/ip_addresses/{}",
        "DOMAIN": "/domains/{}",
        "URL": "/urls",
        "FILE": "/files",
    },
    "ABUSE_IPDB": {
        "BASE": "https://api.abuseipdb.com/api/v2",
        "CHECK": "/check",
        "REPORT": "/report",
    },
}

# Application Settings
SETTINGS = {
    "APP_NAME": "Threat Intelligence Tool",
    "APP_VERSION": "1.0.0",
    "DEBUG": os.getenv("DEBUG", "False").lower() == "true",
    "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO"),
    "MAX_RETRIES": 3,
    "TIMEOUT": 30,
    "CACHE_TTL": 3600,  # 1 hour in seconds
    "MAX_BATCH_SIZE": 100,
}

# Logging Configuration
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        },
        "simple": {
            "format": "%(levelname)s - %(message)s"
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "simple",
            "level": "INFO",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": LOG_DIR / "app.log",
            "formatter": "verbose",
            "level": "DEBUG",
        },
    },
    "root": {
        "handlers": ["console", "file"],
        "level": SETTINGS["LOG_LEVEL"],
    },
}

# UI Settings
UI_SETTINGS = {
    "WINDOW_TITLE": SETTINGS["APP_NAME"],
    "WINDOW_SIZE": (1200, 800),
    "WINDOW_MIN_SIZE": (800, 600),
    "THEME": "light",
    "STYLES": {
        "MAIN_BG_COLOR": "#f0f0f0",
        "ACCENT_COLOR": "#0078d7",
        "ERROR_COLOR": "#ff0000",
        "SUCCESS_COLOR": "#00ff00",
        "WARNING_COLOR": "#ffff00",
    },
}

# Cache Settings
CACHE_SETTINGS = {
    "ENABLED": True,
    "TYPE": "memory",  # or "redis" or "file"
    "TTL": SETTINGS["CACHE_TTL"],
    "MAX_SIZE": 1000,
}

# Export Settings
EXPORT_SETTINGS = {
    "DEFAULT_FORMAT": "csv",
    "AVAILABLE_FORMATS": ["csv", "json", "pdf"],
    "CSV_DELIMITER": ",",
    "ENCODING": "utf-8",
}

# Rate Limiting
RATE_LIMITS = {
    "VIRUSTOTAL": {
        "REQUESTS_PER_MINUTE": 4,
        "BURST": 1,
    },
    "ABUSE_IPDB": {
        "REQUESTS_PER_MINUTE": 60,
        "BURST": 10,
    },
}

# Feature Flags
FEATURES = {
    "ENABLE_CACHE": True,
    "ENABLE_RATE_LIMITING": True,
    "ENABLE_EXPORT": True,
    "ENABLE_BATCH_PROCESSING": True,
    "ENABLE_ADVANCED_SEARCH": True,
}

# Validation Settings
VALIDATION = {
    "MAX_IP_BATCH": 100,
    "MAX_DOMAIN_BATCH": 50,
    "MAX_URL_LENGTH": 2048,
    "SUPPORTED_FILE_TYPES": [".txt", ".csv", ".json"],
}
