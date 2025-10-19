"""
Configuration management for CredStor.

This module handles loading and validating configuration from YAML files,
environment variables, and command-line arguments.
"""

import os
import yaml
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from pathlib import Path

from .user import get_user_config_dir, expand_user_path

logger = logging.getLogger(__name__)

# Global configuration instance
_config: Optional["Config"] = None


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    type: str = "sqlite"
    path: str = "data/credstor.db"
    encryption_key: str = ""
    host: str = "localhost"
    port: int = 5432
    name: str = "credstor"
    username: str = ""
    password: str = ""
    pool_size: int = 5
    max_overflow: int = 10
    echo: bool = False


@dataclass
class SecurityConfig:
    """Security configuration settings."""
    master_password_required: bool = True
    password_hash_algorithm: str = "argon2"
    symmetric_algorithm: str = "AES-256-GCM"
    asymmetric_algorithm: str = "Ed25519"
    client_cert_required: bool = True
    client_cert_path: str = "certs/client.pem"
    client_key_path: str = "certs/client.key"
    ca_cert_path: str = "certs/ca.pem"
    salt_length: int = 32
    key_iterations: int = 100000


@dataclass
class APIConfig:
    """API server configuration settings."""
    host: str = "127.0.0.1"
    port: int = 8080
    rate_limit_requests: int = 100
    rate_limit_window: int = 60
    ssl_enabled: bool = False
    ssl_cert_path: str = "certs/server.pem"
    ssl_key_path: str = "certs/server.key"


@dataclass
class LoggingConfig:
    """Logging configuration settings."""
    level: str = "INFO"
    format: str = "json"
    app_log: str = "logs/credstor.log"
    security_log: str = "logs/security.log"
    audit_log: str = "logs/audit.log"
    max_file_size: str = "10MB"
    backup_count: int = 5
    log_failed_auth: bool = True
    log_successful_auth: bool = False
    log_data_access: bool = True


@dataclass
class CSVImportConfig:
    """CSV import configuration settings."""
    default_separator: str = ","
    default_quote_char: str = '"'
    default_encoding: str = "utf-8"
    field_mappings: Dict[str, str] = field(default_factory=lambda: {
        "property": "property",
        "username": "username",
        "password": "password"
    })
    skip_empty_rows: bool = True
    validate_fields: bool = True


@dataclass
class Config:
    """Main configuration class."""
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    api: APIConfig = field(default_factory=APIConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    csv_import: CSVImportConfig = field(default_factory=CSVImportConfig)


def find_config_file() -> Optional[Path]:
    """
    Find the configuration file in standard locations.
    
    Search order:
    1. CREDSTOR_CONFIG environment variable
    2. config/config.yaml in current directory
    3. User config directory (platform-specific)
    4. /etc/credstor/config.yaml
    
    Returns:
        Path to configuration file or None if not found
    """
    # Check environment variable
    env_config = os.getenv("CREDSTOR_CONFIG")
    if env_config:
        config_path = Path(expand_user_path(env_config))
        if config_path.exists():
            return config_path
        else:
            logger.warning(f"Config file specified in CREDSTOR_CONFIG not found: {env_config}")
    
    # Standard locations
    user_config_dir = get_user_config_dir()
    search_paths = [
        Path("config/config.yaml"),
        Path("config/config.yml"),
        user_config_dir / "config.yaml",
        user_config_dir / "config.yml",
        Path("/etc/credstor/config.yaml"),
    ]
    
    for path in search_paths:
        if path.exists():
            logger.debug(f"Found config file: {path}")
            return path
    
    logger.warning("No configuration file found in standard locations")
    return None


def load_config_from_file(config_path: Path) -> Dict[str, Any]:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid YAML
    """
    try:
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f) or {}
        
        logger.info(f"Configuration loaded from {config_path}")
        return config_data
    
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_path}")
        raise
    
    except yaml.YAMLError as e:
        logger.error(f"Invalid YAML in configuration file {config_path}: {e}")
        raise
    
    except Exception as e:
        logger.error(f"Error loading configuration from {config_path}: {e}")
        raise


def apply_environment_overrides(config_data: Dict[str, Any]) -> None:
    """
    Apply environment variable overrides to configuration.
    
    Environment variables should be prefixed with CREDSTOR_ and use
    double underscores to separate nested keys.
    
    Example: CREDSTOR_DATABASE__TYPE=postgresql
    
    Args:
        config_data: Configuration dictionary to modify
    """
    env_prefix = "CREDSTOR_"
    
    for env_key, env_value in os.environ.items():
        if not env_key.startswith(env_prefix):
            continue
        
        # Convert environment key to config path
        config_key = env_key[len(env_prefix):].lower()
        key_parts = config_key.split("__")
        
        # Navigate to the correct nested dictionary
        current_dict = config_data
        for part in key_parts[:-1]:
            if part not in current_dict:
                current_dict[part] = {}
            current_dict = current_dict[part]
        
        # Set the value
        final_key = key_parts[-1]
        current_dict[final_key] = env_value
        
        logger.debug(f"Applied environment override: {config_key} = {env_value}")


def validate_config(config: Config) -> None:
    """
    Validate configuration settings.
    
    Args:
        config: Configuration to validate
        
    Raises:
        ValueError: If configuration is invalid
    """
    # Database validation
    if config.database.type not in ["sqlite", "postgresql"]:
        raise ValueError(f"Invalid database type: {config.database.type}")
    
    # TODO: Re-enable when we add SQLCipher back
    # if config.database.type == "sqlite" and not config.database.encryption_key:
    #     raise ValueError("SQLite requires an encryption key")
    
    if config.database.type == "postgresql":
        if not config.database.host or not config.database.name:
            raise ValueError("PostgreSQL requires host and database name")
    
    # Security validation
    if config.security.salt_length < 16:
        raise ValueError("Salt length must be at least 16 bytes")
    
    if config.security.key_iterations < 10000:
        raise ValueError("Key iterations must be at least 10,000")
    
    # Certificate paths (if client certificates required)
    if config.security.client_cert_required:
        cert_files = [
            config.security.client_cert_path,
            config.security.client_key_path,
            config.security.ca_cert_path
        ]
        
        for cert_file in cert_files:
            if not os.path.exists(cert_file):
                logger.warning(f"Certificate file not found: {cert_file}")
    
    # API validation
    if not (1 <= config.api.port <= 65535):
        raise ValueError("API port must be between 1 and 65535")
    
    # Logging validation
    log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if config.logging.level.upper() not in log_levels:
        raise ValueError(f"Invalid log level: {config.logging.level}")
    
    logger.info("Configuration validation passed")


def create_config_from_dict(config_data: Dict[str, Any]) -> Config:
    """
    Create Config object from dictionary.
    
    Args:
        config_data: Configuration dictionary
        
    Returns:
        Config object
    """
    # Helper function to safely get nested values
    def get_nested(data: dict, keys: list, default=None):
        for key in keys:
            if isinstance(data, dict) and key in data:
                data = data[key]
            else:
                return default
        return data
    
    # Extract configuration sections
    db_data = config_data.get("database", {})
    security_data = config_data.get("security", {})
    api_data = config_data.get("api", {})
    logging_data = config_data.get("logging", {})
    csv_data = config_data.get("csv_import", {})
    
    # Expand user paths in database configuration
    db_path = db_data.get("path", "data/credstor.db")
    db_path = expand_user_path(db_path)
    
    # Create configuration objects
    config = Config(
        database=DatabaseConfig(
            type=db_data.get("type", "sqlite"),
            path=db_path,
            encryption_key=db_data.get("encryption_key", ""),
            host=db_data.get("host", "localhost"),
            port=db_data.get("port", 5432),
            name=db_data.get("name", "credstor"),
            username=db_data.get("username", ""),
            password=db_data.get("password", ""),
            pool_size=db_data.get("pool_size", 5),
            max_overflow=db_data.get("max_overflow", 10),
            echo=db_data.get("echo", False)
        ),
        security=SecurityConfig(
            master_password_required=security_data.get("master_password_required", True),
            password_hash_algorithm=security_data.get("password_hash_algorithm", "argon2"),
            symmetric_algorithm=security_data.get("symmetric_algorithm", "AES-256-GCM"),
            asymmetric_algorithm=security_data.get("asymmetric_algorithm", "Ed25519"),
            client_cert_required=security_data.get("client_cert_required", True),
            client_cert_path=expand_user_path(security_data.get("client_cert_path", "certs/client.pem")),
            client_key_path=expand_user_path(security_data.get("client_key_path", "certs/client.key")),
            ca_cert_path=expand_user_path(security_data.get("ca_cert_path", "certs/ca.pem")),
            salt_length=security_data.get("salt_length", 32),
            key_iterations=security_data.get("key_iterations", 100000)
        ),
        api=APIConfig(
            host=api_data.get("host", "127.0.0.1"),
            port=api_data.get("port", 8080),
            rate_limit_requests=api_data.get("rate_limit_requests", 100),
            rate_limit_window=api_data.get("rate_limit_window", 60),
            ssl_enabled=api_data.get("ssl_enabled", False),
            ssl_cert_path=expand_user_path(api_data.get("ssl_cert_path", "certs/server.pem")),
            ssl_key_path=expand_user_path(api_data.get("ssl_key_path", "certs/server.key"))
        ),
        logging=LoggingConfig(
            level=logging_data.get("level", "INFO"),
            format=logging_data.get("format", "json"),
            app_log=expand_user_path(logging_data.get("app_log", "logs/credstor.log")),
            security_log=expand_user_path(logging_data.get("security_log", "logs/security.log")),
            audit_log=expand_user_path(logging_data.get("audit_log", "logs/audit.log")),
            max_file_size=logging_data.get("max_file_size", "10MB"),
            backup_count=logging_data.get("backup_count", 5),
            log_failed_auth=logging_data.get("log_failed_auth", True),
            log_successful_auth=logging_data.get("log_successful_auth", False),
            log_data_access=logging_data.get("log_data_access", True)
        ),
        csv_import=CSVImportConfig(
            default_separator=csv_data.get("default_separator", ","),
            default_quote_char=csv_data.get("default_quote_char", '"'),
            default_encoding=csv_data.get("default_encoding", "utf-8"),
            field_mappings=csv_data.get("field_mappings", {
                "property": "property",
                "username": "username",
                "password": "password"
            }),
            skip_empty_rows=csv_data.get("skip_empty_rows", True),
            validate_fields=csv_data.get("validate_fields", True)
        )
    )
    
    return config


def load_config(config_path: Optional[Path] = None) -> Config:
    """
    Load configuration from file and environment variables.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        Configuration object
        
    Raises:
        ValueError: If configuration is invalid
    """
    global _config
    
    # Find configuration file if not specified
    if config_path is None:
        config_path = find_config_file()
    
    # Load configuration data
    config_data = {}
    if config_path:
        config_data = load_config_from_file(config_path)
    else:
        logger.warning("No configuration file found, using defaults")
    
    # Apply environment variable overrides
    apply_environment_overrides(config_data)
    
    # Create configuration object
    config = create_config_from_dict(config_data)
    
    # Validate configuration
    validate_config(config)
    
    # Cache configuration globally
    global _config
    _config = config
    
    logger.info("Configuration loaded successfully")
    return config


def get_config() -> Config:
    """
    Get the current configuration.
    
    Returns:
        Current configuration object
        
    Raises:
        RuntimeError: If configuration hasn't been loaded
    """
    global _config
    if _config is None:
        # Try to load configuration automatically
        _config = load_config()
    
    return _config


def reload_config(config_path: Optional[Path] = None) -> Config:
    """
    Reload configuration from file.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        Reloaded configuration object
    """
    global _config
    _config = None
    return load_config(config_path)