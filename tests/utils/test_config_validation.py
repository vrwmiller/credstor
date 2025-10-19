"""
Tests for enhanced configuration validation.

This module contains tests for the strict configuration validation
features including PostgreSQL security settings and credential validation.
"""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from src.utils.config import (
    Config, DatabaseConfig, SecurityConfig, APIConfig, LoggingConfig, DatabaseCredentials,
    validate_config, validate_postgresql_config, create_database_credentials,
    load_database_credentials
)


class TestEnhancedConfigValidation:
    """Test enhanced configuration validation features."""
    
    def test_validate_postgresql_connection_parameters(self):
        """Test PostgreSQL connection parameter validation."""
        config = Config(
            database=DatabaseConfig(
                type="postgresql",
                host="localhost",
                port=5432,
                name="testdb"
            )
        )
        
        # Should not raise any exception
        validate_config(config)
    
    def test_validate_invalid_postgresql_port(self):
        """Test PostgreSQL port validation."""
        config = Config(
            database=DatabaseConfig(
                type="postgresql",
                host="localhost",
                port=99999,  # Invalid port
                name="testdb"
            )
        )
        
        with pytest.raises(ValueError, match="PostgreSQL port must be between 1 and 65535"):
            validate_config(config)
    
    def test_validate_postgresql_pool_size(self):
        """Test PostgreSQL connection pool validation."""
        config = Config(
            database=DatabaseConfig(
                type="postgresql",
                host="localhost",
                port=5432,
                name="testdb",
                pool_size=0  # Invalid pool size
            )
        )
        
        with pytest.raises(ValueError, match="Database pool size must be at least 1"):
            validate_config(config)
    
    def test_validate_postgresql_max_overflow(self):
        """Test PostgreSQL max overflow validation."""
        config = Config(
            database=DatabaseConfig(
                type="postgresql",
                host="localhost",
                port=5432,
                name="testdb",
                max_overflow=-1  # Invalid overflow
            )
        )
        
        with pytest.raises(ValueError, match="Database max overflow must be non-negative"):
            validate_config(config)
    
    def test_validate_cryptographic_algorithms(self):
        """Test cryptographic algorithm validation."""
        # Valid algorithms
        config = Config(
            security=SecurityConfig(
                password_hash_algorithm="argon2",
                symmetric_algorithm="AES-256-GCM",
                asymmetric_algorithm="Ed25519"
            )
        )
        validate_config(config)
        
        # Invalid hash algorithm
        config.security.password_hash_algorithm = "md5"
        with pytest.raises(ValueError, match="Invalid password hash algorithm"):
            validate_config(config)
        
        # Invalid symmetric algorithm
        config.security.password_hash_algorithm = "argon2"
        config.security.symmetric_algorithm = "DES"
        with pytest.raises(ValueError, match="Invalid symmetric algorithm"):
            validate_config(config)
        
        # Invalid asymmetric algorithm
        config.security.symmetric_algorithm = "AES-256-GCM"
        config.security.asymmetric_algorithm = "RSA-1024"
        with pytest.raises(ValueError, match="Invalid asymmetric algorithm"):
            validate_config(config)
    
    def test_validate_api_security_warnings(self):
        """Test API security validation warnings."""
        config = Config(
            api=APIConfig(
                host="0.0.0.0",  # Should trigger warning
                ssl_enabled=False,  # Should trigger warning
                rate_limit_requests=0  # Should raise error
            )
        )
        
        with pytest.raises(ValueError, match="Rate limit requests must be at least 1"):
            validate_config(config)
    
    def test_validate_rate_limiting(self):
        """Test rate limiting validation."""
        config = Config(
            api=APIConfig(
                rate_limit_requests=1,
                rate_limit_window=0  # Invalid window
            )
        )
        
        with pytest.raises(ValueError, match="Rate limit window must be at least 1 second"):
            validate_config(config)
    
    @patch('src.utils.config.logger')
    def test_security_warnings_logged(self, mock_logger):
        """Test that security warnings are properly logged."""
        config = Config(
            database=DatabaseConfig(
                type="postgresql",
                host="0.0.0.0"
            ),
            api=APIConfig(
                ssl_enabled=False,
                rate_limit_requests=15000
            ),
            logging=LoggingConfig(
                log_failed_auth=False,
                log_data_access=False
            )
        )
        
        validate_config(config)
        
        # Check that warnings were logged
        warning_calls = [call for call in mock_logger.warning.call_args_list]
        assert len(warning_calls) >= 2  # Should have multiple warnings


class TestDatabaseCredentialsValidation:
    """Test database credentials validation features."""
    
    def test_credentials_basic_validation(self):
        """Test basic credentials validation."""
        creds = DatabaseCredentials(
            username="secure_user_123",
            password="secure_complex_password_987654321"
        )
        
        # Should not raise exception
        creds.validate_security()
    
    def test_credentials_password_length(self):
        """Test password length validation."""
        creds = DatabaseCredentials(
            username="testuser",
            password="short"  # Too short
        )
        
        with pytest.raises(ValueError, match="Database password must be at least 12 characters long"):
            creds.validate_security()
    
    def test_credentials_weak_passwords(self):
        """Test weak password detection."""
        weak_passwords = ["password", "123456", "admin", "postgres"]
        
        for weak_pass in weak_passwords:
            creds = DatabaseCredentials(
                username="testuser",
                password=weak_pass  # Use weak password directly (some are long enough)
            )
            
            # Only test passwords that are long enough to pass length check
            if len(weak_pass) >= 12:
                with pytest.raises(ValueError, match="Database password is too weak"):
                    creds.validate_security()
        
        # Test specific case with "password" (8 chars, needs to be longer)
        creds = DatabaseCredentials(
            username="testuser",
            password="password123456"  # Contains weak word but is longer
        )
        
        with pytest.raises(ValueError, match="Database password is too weak"):
            creds.validate_security()
    
    def test_credentials_username_validation(self):
        """Test username validation."""
        creds = DatabaseCredentials(
            username="xy",  # Too short
            password="secure_complex_password_987654321"
        )
        
        with pytest.raises(ValueError, match="Database username must be at least 3 characters long"):
            creds.validate_security()
    
    @patch('src.utils.config.logger')
    def test_default_username_warning(self, mock_logger):
        """Test warning for default usernames."""
        creds = DatabaseCredentials(
            username="admin",
            password="secure_complex_password_987654321"
        )
        
        creds.validate_security()
        
        # Should log warning about default username
        mock_logger.warning.assert_called()
        warning_msg = mock_logger.warning.call_args[0][0]
        assert "default username" in warning_msg


class TestPostgreSQLValidation:
    """Test PostgreSQL-specific validation."""
    
    def test_postgresql_config_validation(self):
        """Test PostgreSQL configuration validation."""
        db_config = DatabaseConfig(
            type="postgresql",
            host="localhost",
            port=5432,
            name="credstor",
            pool_size=5,
            max_overflow=10
        )
        
        credentials = DatabaseCredentials(
            username="testuser",
            password="test_password_123456"
        )
        
        # Should not raise exception
        validate_postgresql_config(db_config, credentials)
    
    def test_postgresql_missing_host(self):
        """Test PostgreSQL missing host validation."""
        db_config = DatabaseConfig(
            type="postgresql",
            host="",  # Missing host
            name="credstor"
        )
        
        credentials = DatabaseCredentials(
            username="testuser",
            password="test_password_123456"
        )
        
        with pytest.raises(ValueError, match="PostgreSQL host is required"):
            validate_postgresql_config(db_config, credentials)
    
    def test_postgresql_missing_database_name(self):
        """Test PostgreSQL missing database name validation."""
        db_config = DatabaseConfig(
            type="postgresql",
            host="localhost",
            name=""  # Missing database name
        )
        
        credentials = DatabaseCredentials(
            username="testuser",
            password="test_password_123456"
        )
        
        with pytest.raises(ValueError, match="PostgreSQL database name is required"):
            validate_postgresql_config(db_config, credentials)
    
    @patch('src.utils.config.logger')
    def test_postgresql_system_database_warning(self, mock_logger):
        """Test warning for system database usage."""
        db_config = DatabaseConfig(
            type="postgresql",
            host="localhost",
            name="postgres"  # System database
        )
        
        credentials = DatabaseCredentials(
            username="testuser",
            password="test_password_123456"
        )
        
        validate_postgresql_config(db_config, credentials)
        
        # Should log warning about system database
        mock_logger.warning.assert_called()
        warning_msg = mock_logger.warning.call_args[0][0]
        assert "system database" in warning_msg
    
    @patch('src.utils.config.logger')
    def test_postgresql_large_connection_pool_warning(self, mock_logger):
        """Test warning for large connection pools."""
        db_config = DatabaseConfig(
            type="postgresql",
            host="localhost",
            name="credstor",
            pool_size=40,
            max_overflow=20  # Total 60 connections
        )
        
        credentials = DatabaseCredentials(
            username="testuser",
            password="test_password_123456"
        )
        
        validate_postgresql_config(db_config, credentials)
        
        # Should log warning about large connection pool
        mock_logger.warning.assert_called()
        warning_msg = mock_logger.warning.call_args[0][0]
        assert "Large connection pool" in warning_msg


class TestCredentialsFileValidation:
    """Test database credentials file validation."""
    
    def test_create_credentials_with_validation(self):
        """Test creating credentials with validation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mock the config path
            with patch('src.utils.config.get_credstor_conf_path') as mock_path:
                conf_path = Path(temp_dir) / "credstor.conf"
                mock_path.return_value = conf_path
                
                # Should work with valid credentials
                create_database_credentials(
                    username="valid_user_name",
                    password="valid_password_123456789"
                )
                
                assert conf_path.exists()
                assert oct(conf_path.stat().st_mode & 0o777) == "0o400"
    
    def test_create_credentials_validation_failure(self):
        """Test credential creation with validation failure."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('src.utils.config.get_credstor_conf_path') as mock_path:
                conf_path = Path(temp_dir) / "credstor.conf"
                mock_path.return_value = conf_path
                
                # Should fail with weak password
                with pytest.raises(ValueError, match="Database password is too weak"):
                    create_database_credentials(
                        username="testuser",
                        password="password123456"  # Weak password (contains "password")
                    )
    
    @patch('src.utils.config.get_config')
    def test_load_credentials_conditional_validation(self, mock_get_config):
        """Test conditional validation based on database type."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('src.utils.config.get_credstor_conf_path') as mock_path:
                conf_path = Path(temp_dir) / "credstor.conf"
                mock_path.return_value = conf_path
                
                # Create a credentials file with weak password
                import yaml
                creds_data = {
                    'database': {
                        'username': 'testuser',
                        'password': 'weak',  # Short password
                        'auth_token': ''
                    }
                }
                
                with open(conf_path, 'w') as f:
                    yaml.dump(creds_data, f)
                conf_path.chmod(0o400)
                
                # Mock SQLite config - should NOT validate password
                mock_config = Mock()
                mock_config.database.type = "sqlite"
                mock_get_config.return_value = mock_config
                
                credentials = load_database_credentials()
                assert credentials.username == "testuser"
                
                # Mock PostgreSQL config - should validate password
                mock_config.database.type = "postgresql"
                
                with pytest.raises(ValueError, match="Database password must be at least 12 characters long"):
                    load_database_credentials()