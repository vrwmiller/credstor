"""
Tests for configuration management.
"""

import pytest
import tempfile
import os
import yaml
from pathlib import Path

from src.utils.config import (
    Config, DatabaseConfig, SecurityConfig, APIConfig,
    load_config, get_config, reload_config, validate_config,
    find_config_file, load_config_from_file, apply_environment_overrides
)


@pytest.mark.unit
class TestConfigModels:
    """Test configuration model classes."""
    
    def test_database_config_defaults(self):
        """Test DatabaseConfig default values."""
        config = DatabaseConfig()
        
        assert config.type == "postgresql"
        assert config.path == "data/credstor.db"
        assert config.host == "localhost"
        assert config.port == 5432
        assert config.pool_size == 5
        assert config.echo is False
    
    def test_security_config_defaults(self):
        """Test SecurityConfig default values."""
        config = SecurityConfig()
        
        assert config.master_password_required is True
        assert config.password_hash_algorithm == "argon2"
        assert config.symmetric_algorithm == "AES-256-GCM"
        assert config.asymmetric_algorithm == "Ed25519"
        assert config.salt_length == 32
        assert config.key_iterations == 100000
    
    def test_api_config_defaults(self):
        """Test APIConfig default values."""
        config = APIConfig()
        
        assert config.host == "127.0.0.1"
        assert config.port == 8080
        assert config.rate_limit_requests == 100
        assert config.ssl_enabled is False
    
    def test_main_config_defaults(self):
        """Test main Config class with default values."""
        config = Config()
        
        assert isinstance(config.database, DatabaseConfig)
        assert isinstance(config.security, SecurityConfig)
        assert isinstance(config.api, APIConfig)


@pytest.mark.unit
class TestConfigValidation:
    """Test configuration validation."""
    
    def test_valid_config_passes(self):
        """Test that valid configuration passes validation."""
        config = Config(
            database=DatabaseConfig(
                type="sqlite",
                encryption_key="dGVzdF9rZXlfMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A="  # Valid base64
            )
        )
        
        # Should not raise any exception
        validate_config(config)
    
    def test_invalid_database_type_fails(self):
        """Test that invalid database type fails validation."""
        config = Config(
            database=DatabaseConfig(type="invalid_db_type")
        )
        
        with pytest.raises(ValueError, match="Invalid database type"):
            validate_config(config)
    
    def test_missing_sqlite_encryption_key_passes(self):
        """Test that SQLite without encryption key passes validation (using app-level encryption)."""
        config = Config(
            database=DatabaseConfig(
                type="sqlite",
                encryption_key=""  # Missing key is OK with app-level encryption
            )
        )
        
        # Should not raise an exception
        validate_config(config)
    
    def test_invalid_port_fails(self):
        """Test that invalid port number fails validation."""
        config = Config(
            api=APIConfig(port=99999)  # Invalid port
        )
        
        with pytest.raises(ValueError, match="API port must be between"):
            validate_config(config)
    
    def test_weak_security_settings_fail(self):
        """Test that weak security settings fail validation."""
        config = Config(
            security=SecurityConfig(
                salt_length=8,  # Too short
                key_iterations=1000  # Too few
            )
        )
        
        with pytest.raises(ValueError, match="Salt length must be at least"):
            validate_config(config)


@pytest.mark.unit
class TestConfigLoading:
    """Test configuration file loading."""
    
    def test_load_config_from_yaml_file(self):
        """Test loading configuration from YAML file."""
        config_data = {
            "database": {
                "type": "sqlite",
                "path": "test.db",
                "encryption_key": "dGVzdF9rZXlfMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A="
            },
            "api": {
                "host": "0.0.0.0",
                "port": 9090
            }
        }
        
        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name
        
        try:
            # Load config from file
            loaded_data = load_config_from_file(Path(temp_path))
            
            assert loaded_data["database"]["type"] == "sqlite"
            assert loaded_data["database"]["path"] == "test.db"
            assert loaded_data["api"]["host"] == "0.0.0.0"
            assert loaded_data["api"]["port"] == 9090
            
        finally:
            os.unlink(temp_path)
    
    def test_load_invalid_yaml_file_fails(self):
        """Test that loading invalid YAML file raises error."""
        # Create temporary file with invalid YAML
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: content: [")
            temp_path = f.name
        
        try:
            with pytest.raises(yaml.YAMLError):
                load_config_from_file(Path(temp_path))
        finally:
            os.unlink(temp_path)
    
    def test_load_nonexistent_file_fails(self):
        """Test that loading non-existent file raises error."""
        with pytest.raises(FileNotFoundError):
            load_config_from_file(Path("/nonexistent/config.yaml"))


@pytest.mark.unit
class TestEnvironmentOverrides:
    """Test environment variable configuration overrides."""
    
    def test_environment_variable_override(self):
        """Test that environment variables override config values."""
        config_data = {
            "database": {"type": "sqlite"},
            "api": {"port": 8080}
        }
        
        # Set environment variables
        os.environ["CREDSTOR_DATABASE__TYPE"] = "postgresql"
        os.environ["CREDSTOR_API__PORT"] = "9090"
        
        try:
            apply_environment_overrides(config_data)
            
            assert config_data["database"]["type"] == "postgresql"
            assert config_data["api"]["port"] == "9090"
            
        finally:
            # Clean up environment variables
            del os.environ["CREDSTOR_DATABASE__TYPE"]
            del os.environ["CREDSTOR_API__PORT"]
    
    def test_nested_environment_override(self):
        """Test nested environment variable overrides."""
        config_data = {"logging": {}}
        
        os.environ["CREDSTOR_LOGGING__LEVEL"] = "DEBUG"
        os.environ["CREDSTOR_LOGGING__FORMAT"] = "text"
        
        try:
            apply_environment_overrides(config_data)
            
            assert config_data["logging"]["level"] == "DEBUG"
            assert config_data["logging"]["format"] == "text"
            
        finally:
            del os.environ["CREDSTOR_LOGGING__LEVEL"]
            del os.environ["CREDSTOR_LOGGING__FORMAT"]


@pytest.mark.integration
class TestConfigIntegration:
    """Integration tests for configuration system."""
    
    def test_full_config_loading_cycle(self):
        """Test complete configuration loading process."""
        config_data = {
            "database": {
                "type": "sqlite",
                "path": "integration_test.db",
                "encryption_key": "dGVzdF9rZXlfMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A="
            },
            "security": {
                "master_password_required": False,
                "key_iterations": 50000
            },
            "api": {
                "host": "127.0.0.1",
                "port": 8081
            }
        }
        
        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name
        
        try:
            # Load complete configuration
            config = load_config(Path(temp_path))
            
            # Verify all sections loaded correctly
            assert config.database.type == "sqlite"
            assert config.database.path == "integration_test.db"
            assert config.security.master_password_required is False
            assert config.security.key_iterations == 50000
            assert config.api.host == "127.0.0.1"
            assert config.api.port == 8081
            
            # Test that config is accessible globally
            global_config = get_config()
            assert global_config.database.type == "sqlite"
            
        finally:
            os.unlink(temp_path)
            # Reset global config
            import src.utils.config as config_module
            config_module._config = None