"""
Additional CLI error handling tests for coverage.

Quick tests to cover CLI error paths and reach 80% coverage target.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner

from src.cli.credstor import cli


class TestCLIErrorHandling:
    """Test CLI error handling paths for coverage."""
    
    def test_cli_database_connection_error(self):
        """Test CLI handling of database connection errors."""
        runner = CliRunner()
        
        with patch('src.cli.credstor.init_database') as mock_init:
            mock_init.side_effect = Exception("Database connection failed")
            
            result = runner.invoke(cli, ['health'])
            assert result.exit_code != 0
    
    def test_cli_config_loading_error(self):
        """Test CLI handling of configuration loading errors."""
        runner = CliRunner()
        
        with patch('src.cli.credstor.get_config') as mock_config:
            mock_config.side_effect = Exception("Config loading failed")
            
            result = runner.invoke(cli, ['--help'])
            # Help should still work
            assert result.exit_code == 0
    
    @patch('src.cli.credstor.get_db')
    def test_add_command_database_error(self, mock_db):
        """Test add command with database error."""
        runner = CliRunner()
        
        mock_session = Mock()
        mock_session.add.side_effect = Exception("Database error")
        mock_db.return_value.__enter__.return_value = mock_session
        
        result = runner.invoke(cli, [
            'add', 
            '--property', 'test.com',
            '--username', 'testuser',
            '--password', 'testpass'
        ])
        
        assert result.exit_code != 0
    
    @patch('src.cli.credstor.get_db')
    def test_search_command_database_error(self, mock_db):
        """Test search command with database error."""
        runner = CliRunner()
        
        mock_session = Mock()
        mock_session.query.side_effect = Exception("Database error")
        mock_db.return_value.__enter__.return_value = mock_session
        
        result = runner.invoke(cli, ['search', 'test'])
        assert result.exit_code != 0
    
    def test_init_auth_file_permission_error(self):
        """Test init-auth with file permission error."""
        runner = CliRunner()
        
        with patch('src.cli.credstor.create_database_credentials') as mock_create:
            mock_create.side_effect = PermissionError("Permission denied")
            
            result = runner.invoke(cli, ['init-auth'], input='testuser\ntestpass123456\n')
            assert result.exit_code != 0
    
    @patch('src.cli.credstor.validate_config')
    def test_config_validation_error(self, mock_validate):
        """Test configuration validation error handling."""
        runner = CliRunner()
        
        mock_validate.side_effect = ValueError("Invalid configuration")
        
        result = runner.invoke(cli, ['health'])
        assert result.exit_code != 0


class TestCryptoErrorPaths:
    """Test crypto module error paths for coverage."""
    
    def test_encrypt_with_invalid_key(self):
        """Test encryption with invalid key."""
        from src.security.crypto import encrypt_data
        
        with pytest.raises(Exception):
            encrypt_data(b"test data", b"invalid_key")
    
    def test_decrypt_with_wrong_key(self):
        """Test decryption with wrong key."""
        from src.security.crypto import encrypt_data, decrypt_data, generate_key
        
        key1 = generate_key()
        key2 = generate_key()
        
        encrypted = encrypt_data(b"test data", key1)
        
        with pytest.raises(Exception):
            decrypt_data(encrypted, key2)
    
    def test_hash_password_with_invalid_algorithm(self):
        """Test password hashing with invalid algorithm."""
        from src.security.crypto import hash_password
        
        # This should use the default algorithm and not fail
        hashed = hash_password("test_password", algorithm="invalid")
        assert hashed is not None


class TestLoggingErrorPaths:
    """Test logging configuration error paths."""
    
    @patch('src.utils.logging_config.os.makedirs')
    def test_logging_directory_creation_error(self, mock_makedirs):
        """Test logging setup with directory creation error."""
        from src.utils.logging_config import setup_logging
        
        mock_makedirs.side_effect = PermissionError("Permission denied")
        
        # Should handle error gracefully
        config = Mock()
        config.logging.app_log = "logs/app.log"
        config.logging.security_log = "logs/security.log"
        config.logging.audit_log = "logs/audit.log"
        config.logging.level = "INFO"
        config.logging.format = "json"
        
        # Should not raise exception
        setup_logging(config)
    
    def test_invalid_log_level(self):
        """Test logging with invalid log level."""
        from src.utils.logging_config import setup_logging
        
        config = Mock()
        config.logging.level = "INVALID"
        config.logging.format = "json"
        config.logging.app_log = "logs/app.log"
        config.logging.security_log = "logs/security.log"
        config.logging.audit_log = "logs/audit.log"
        
        # Should handle gracefully and use default
        setup_logging(config)


class TestDatabaseErrorPaths:
    """Test database error handling paths."""
    
    @patch('src.database.connection.create_engine')
    def test_database_engine_creation_error(self, mock_create_engine):
        """Test database engine creation error."""
        from src.database.connection import create_database_engine
        
        mock_create_engine.side_effect = Exception("Engine creation failed")
        
        with pytest.raises(Exception):
            create_database_engine()
    
    @patch('src.database.connection.SessionLocal')
    def test_database_session_error(self, mock_session_local):
        """Test database session creation error."""
        from src.database.connection import get_database_session
        
        mock_session_local.side_effect = Exception("Session creation failed")
        
        with pytest.raises(Exception):
            get_database_session()