"""
Logging configuration for CredStor.

This module sets up structured logging for security events, audit trails,
and application events while ensuring no sensitive data is logged.
"""

import os
import sys
import logging
import logging.handlers
from typing import Any, Dict
from pathlib import Path

import structlog
from structlog.stdlib import LoggerFactory

try:
    from .config import get_config
except ImportError:
    # Fallback for direct execution
    from config import get_config


def sanitize_log_data(data: Any) -> Any:
    """
    Sanitize log data to remove sensitive information.
    
    Args:
        data: Data to sanitize
        
    Returns:
        Sanitized data with sensitive fields removed/masked
    """
    if isinstance(data, dict):
        sanitized = {}
        sensitive_keys = {
            'password', 'passwd', 'pwd', 'secret', 'token', 'key', 'api_key',
            'private_key', 'passphrase', 'auth', 'authorization', 'credential',
            'credentials', 'session_id', 'session_key'
        }
        
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if key contains sensitive information
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                if value:
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = None
            else:
                sanitized[key] = sanitize_log_data(value)
        
        return sanitized
    
    elif isinstance(data, (list, tuple)):
        return [sanitize_log_data(item) for item in data]
    
    elif isinstance(data, str):
        # Check if string looks like sensitive data
        data_lower = data.lower()
        sensitive_patterns = ['password=', 'token=', 'key=', 'secret=', 'auth=']
        
        if any(pattern in data_lower for pattern in sensitive_patterns):
            return "[REDACTED]"
        
        # Mask potential tokens/keys (long alphanumeric strings)
        if len(data) > 20 and data.replace('-', '').replace('_', '').isalnum():
            return f"{data[:4]}...{data[-4:]}"
    
    return data


def add_sanitization_processor(logger, method_name, event_dict):
    """Structlog processor to sanitize sensitive data."""
    return sanitize_log_data(event_dict)


def setup_file_handler(log_file: str, max_size: str = "10MB", backup_count: int = 5) -> logging.handlers.RotatingFileHandler:
    """
    Set up a rotating file handler.
    
    Args:
        log_file: Path to log file
        max_size: Maximum file size before rotation
        backup_count: Number of backup files to keep
        
    Returns:
        Configured file handler
    """
    # Create log directory if it doesn't exist
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Convert size string to bytes
    size_multipliers = {
        'KB': 1024,
        'MB': 1024 * 1024,
        'GB': 1024 * 1024 * 1024
    }
    
    max_size_upper = max_size.upper()
    max_bytes = 10 * 1024 * 1024  # Default 10MB
    
    for unit, multiplier in size_multipliers.items():
        if max_size_upper.endswith(unit):
            size_value = int(max_size_upper[:-len(unit)])
            max_bytes = size_value * multiplier
            break
    
    # Create rotating file handler
    handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    
    return handler


def setup_logging(level: str = "INFO", config_override: Dict[str, Any] = None) -> None:
    """
    Set up logging configuration for CredStor.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        config_override: Optional configuration overrides
    """
    try:
        # Get configuration
        config = get_config()
        log_config = config.logging
        
        # Apply any overrides
        if config_override:
            for key, value in config_override.items():
                setattr(log_config, key, value)
        
        # Override level if specified
        if level:
            log_config.level = level
        
        # Configure structlog
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                add_sanitization_processor,  # Sanitize sensitive data
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer() if log_config.format == "json" else structlog.processors.KeyValueRenderer(),
            ],
            context_class=dict,
            logger_factory=LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        # Set up root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, log_config.level.upper()))
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(getattr(logging, log_config.level.upper()))
        root_logger.addHandler(console_handler)
        
        # Application log file handler
        if log_config.app_log:
            app_handler = setup_file_handler(
                log_config.app_log,
                log_config.max_file_size,
                log_config.backup_count
            )
            
            if log_config.format == "json":
                app_formatter = logging.Formatter('%(message)s')
            else:
                app_formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            
            app_handler.setFormatter(app_formatter)
            app_handler.setLevel(getattr(logging, log_config.level.upper()))
            root_logger.addHandler(app_handler)
        
        # Security log handler (separate file for security events)
        if log_config.security_log:
            security_handler = setup_file_handler(
                log_config.security_log,
                log_config.max_file_size,
                log_config.backup_count
            )
            
            security_formatter = logging.Formatter(
                '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
            )
            security_handler.setFormatter(security_formatter)
            security_handler.setLevel(logging.WARNING)  # Only warnings and above for security
            
            # Create security logger
            security_logger = logging.getLogger('credstor.security')
            security_logger.addHandler(security_handler)
            security_logger.setLevel(logging.WARNING)
            security_logger.propagate = False  # Don't propagate to root logger
        
        # Audit log handler (separate file for audit events)
        if log_config.audit_log:
            audit_handler = setup_file_handler(
                log_config.audit_log,
                log_config.max_file_size,
                log_config.backup_count
            )
            
            audit_formatter = logging.Formatter(
                '%(asctime)s - AUDIT - %(message)s'
            )
            audit_handler.setFormatter(audit_formatter)
            audit_handler.setLevel(logging.INFO)
            
            # Create audit logger
            audit_logger = logging.getLogger('credstor.audit')
            audit_logger.addHandler(audit_handler)
            audit_logger.setLevel(logging.INFO)
            audit_logger.propagate = False  # Don't propagate to root logger
        
        # Set specific logger levels
        logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)  # Reduce SQL noise
        logging.getLogger('urllib3').setLevel(logging.WARNING)  # Reduce HTTP noise
        
        logging.info("Logging configuration initialized")
        
    except Exception as e:
        # Fall back to basic logging if configuration fails
        logging.basicConfig(
            level=getattr(logging, level.upper() if level else "INFO"),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler(sys.stdout)]
        )
        logging.error(f"Failed to set up logging configuration: {e}")


def get_security_logger():
    """Get the security event logger."""
    return logging.getLogger('credstor.security')


def get_audit_logger():
    """Get the audit event logger."""
    return logging.getLogger('credstor.audit')


def log_security_event(
    event_type: str,
    severity: str,
    description: str,
    context: Dict[str, Any] = None,
    user_info: Dict[str, Any] = None
):
    """
    Log a security event.
    
    Args:
        event_type: Type of security event (AUTH_FAILED, ENCRYPTION_ERROR, etc.)
        severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
        description: Human-readable description
        context: Additional context information
        user_info: User/client information (will be sanitized)
    """
    security_logger = get_security_logger()
    
    log_data = {
        'event_type': event_type,
        'severity': severity,
        'description': description
    }
    
    if context:
        log_data['context'] = sanitize_log_data(context)
    
    if user_info:
        log_data['user_info'] = sanitize_log_data(user_info)
    
    # Log at appropriate level based on severity
    if severity == 'CRITICAL':
        security_logger.critical("Security event", extra=log_data)
    elif severity == 'HIGH':
        security_logger.error("Security event", extra=log_data)
    elif severity == 'MEDIUM':
        security_logger.warning("Security event", extra=log_data)
    else:
        security_logger.info("Security event", extra=log_data)


def log_audit_event(
    action: str,
    resource: str,
    result: str,
    context: Dict[str, Any] = None,
    user_info: Dict[str, Any] = None
):
    """
    Log an audit event.
    
    Args:
        action: Action performed (CREATE, READ, UPDATE, DELETE, etc.)
        resource: Resource affected (credential, configuration, etc.)
        result: Result of the action (SUCCESS, FAILURE, PARTIAL)
        context: Additional context information
        user_info: User/client information (will be sanitized)
    """
    audit_logger = get_audit_logger()
    
    log_data = {
        'action': action,
        'resource': resource,
        'result': result
    }
    
    if context:
        log_data['context'] = sanitize_log_data(context)
    
    if user_info:
        log_data['user_info'] = sanitize_log_data(user_info)
    
    audit_logger.info("Audit event", extra=log_data)