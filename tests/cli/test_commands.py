"""
Tests for CLI functionality.
"""

import pytest
from click.testing import CliRunner
from unittest.mock import patch, MagicMock
import tempfile
import os

from src.cli.credstor import cli


@pytest.fixture
def cli_runner():
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def mock_config():
    """Mock configuration for CLI tests."""
    with patch('src.cli.credstor.load_config') as mock_load, \
         patch('src.cli.credstor.get_config') as mock_get:
        
        mock_config_obj = MagicMock()
        mock_config_obj.database.type = "sqlite"
        mock_config_obj.database.path = "test.db"
        
        mock_load.return_value = mock_config_obj
        mock_get.return_value = mock_config_obj
        
        yield mock_config_obj


@pytest.fixture
def mock_database():
    """Mock database operations for CLI tests."""
    with patch('src.cli.credstor.init_database') as mock_init, \
         patch('src.cli.credstor.get_db') as mock_db:
        
        mock_session = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_session
        mock_db.return_value.__exit__.return_value = None
        
        yield mock_session


@pytest.mark.cli
class TestCLIBasics:
    """Test basic CLI functionality."""
    
    def test_cli_help(self, cli_runner):
        """Test CLI help command."""
        result = cli_runner.invoke(cli, ['--help'])
        
        assert result.exit_code == 0
        assert "CredStor - Secure Personal Credential Vault" in result.output
        assert "Commands:" in result.output
    
    def test_cli_version_info(self, cli_runner, mock_config, mock_database):
        """Test CLI shows version information."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key:
            mock_key.return_value = b"test_key" * 4  # 32 bytes
            
            result = cli_runner.invoke(cli, ['health'])
            
            assert result.exit_code == 0


@pytest.mark.cli
class TestHealthCommand:
    """Test health check command."""
    
    def test_health_check_success(self, cli_runner, mock_config, mock_database):
        """Test successful health check."""
        with patch('src.cli.credstor.check_database_health') as mock_health, \
             patch('src.cli.credstor.get_encryption_key') as mock_key:
            
            mock_key.return_value = b"test_key" * 4
            mock_health.return_value = {
                "database_connected": True,
                "tables_exist": True,
                "encryption_working": True,
                "error": None
            }
            
            result = cli_runner.invoke(cli, ['health'])
            
            assert result.exit_code == 0
            assert "OK Connected" in result.output
            assert "OK Present" in result.output
            assert "OK Working" in result.output
    
    def test_health_check_failure(self, cli_runner, mock_config, mock_database):
        """Test health check with failures."""
        with patch('src.cli.credstor.check_database_health') as mock_health, \
             patch('src.cli.credstor.get_encryption_key') as mock_key:
            
            mock_key.return_value = b"test_key" * 4
            mock_health.return_value = {
                "database_connected": False,
                "tables_exist": False,
                "encryption_working": False,
                "error": "Database connection failed"
            }
            
            result = cli_runner.invoke(cli, ['health'])
            
            assert result.exit_code == 0
            assert "X Failed" in result.output
            assert "Database connection failed" in result.output


@pytest.mark.cli
class TestAddCommand:
    """Test credential addition command."""
    
    def test_add_credential_basic(self, cli_runner, mock_config, mock_database):
        """Test adding a basic credential."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key, \
             patch('src.cli.credstor.encrypt_credential_fields') as mock_encrypt, \
             patch('src.cli.credstor.Credential') as mock_cred_class:
            
            mock_key.return_value = b"test_key" * 4
            mock_encrypt.return_value = {"password_encrypted": b"encrypted"}
            
            # Mock credential object
            mock_credential = MagicMock()
            mock_credential.id = "12345678-1234-1234-1234-123456789012"
            mock_credential.property = "test.com"
            mock_credential.username = "testuser"
            mock_cred_class.return_value = mock_credential
            
            # Mock database refresh
            mock_database.refresh.return_value = None
            
            result = cli_runner.invoke(cli, [
                'add',
                '--property', 'test.com',
                '--username', 'testuser',
                '--password', 'testpass123'
            ])
            
            assert result.exit_code == 0
            assert "Credential added successfully" in result.output
            assert "test.com" in result.output
            assert "testuser" in result.output
    
    def test_add_credential_missing_required(self, cli_runner, mock_config, mock_database):
        """Test adding credential with missing required fields."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key:
            mock_key.return_value = b"test_key" * 4
            
            result = cli_runner.invoke(cli, [
                'add',
                '--property', 'test.com'
                # Missing username and password
            ])
            
            assert result.exit_code != 0
    
    def test_add_credential_with_optional_fields(self, cli_runner, mock_config, mock_database):
        """Test adding credential with optional fields."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key, \
             patch('src.cli.credstor.encrypt_credential_fields') as mock_encrypt, \
             patch('src.cli.credstor.Credential') as mock_cred_class:
            
            mock_key.return_value = b"test_key" * 4
            mock_encrypt.return_value = {
                "password_encrypted": b"encrypted_pass",
                "api_token_encrypted": b"encrypted_token",
                "notes_encrypted": b"encrypted_notes"
            }
            
            mock_credential = MagicMock()
            mock_credential.id = "12345678-1234-1234-1234-123456789012"
            mock_cred_class.return_value = mock_credential
            
            result = cli_runner.invoke(cli, [
                'add',
                '--property', 'test.com',
                '--username', 'testuser',
                '--password', 'testpass123',
                '--api-token', 'token123',
                '--notes', 'Test notes'
            ])
            
            assert result.exit_code == 0


@pytest.mark.cli
class TestSearchCommand:
    """Test credential search command."""
    
    def test_search_credentials_found(self, cli_runner, mock_config, mock_database):
        """Test searching credentials with results."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key:
            mock_key.return_value = b"test_key" * 4
            
            # Mock credential results
            mock_credential = MagicMock()
            mock_credential.id = "12345678-1234-1234-1234-123456789012"
            mock_credential.property = "test.com"
            mock_credential.username = "testuser"
            mock_credential.password_encrypted = b"encrypted"
            mock_credential.api_token_encrypted = None
            mock_credential.created_at.strftime.return_value = "2023-01-01"
            
            mock_query = mock_database.query.return_value
            mock_query.filter.return_value = mock_query
            mock_query.limit.return_value = mock_query
            mock_query.all.return_value = [mock_credential]
            
            result = cli_runner.invoke(cli, [
                'search',
                '--property', 'test'
            ])
            
            assert result.exit_code == 0
            assert "test.com" in result.output
            assert "testuser" in result.output
    
    def test_search_credentials_not_found(self, cli_runner, mock_config, mock_database):
        """Test searching credentials with no results."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key:
            mock_key.return_value = b"test_key" * 4
            
            mock_query = mock_database.query.return_value
            mock_query.filter.return_value = mock_query
            mock_query.limit.return_value = mock_query
            mock_query.all.return_value = []
            
            result = cli_runner.invoke(cli, [
                'search',
                '--property', 'nonexistent'
            ])
            
            assert result.exit_code == 0
            assert "No credentials found" in result.output


@pytest.mark.cli
class TestImportCommand:
    """Test CSV import command."""
    
    def test_import_csv_dry_run(self, cli_runner, test_db):
        """Test CSV import with dry run."""
        # Create temporary CSV file
        csv_content = "property,username,password\ntest.com,user,pass123\nexample.com,admin,secret456"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(csv_content)
            temp_path = f.name
        
        try:
            result = cli_runner.invoke(cli, [
                'import-csv',
                '--file', temp_path,
                '--dry-run'
            ])
            
            assert result.exit_code == 0
            assert "Preview complete" in result.output or "Would import" in result.output
        
        finally:
            os.unlink(temp_path)
    
    def test_import_csv_missing_file(self, cli_runner, mock_config, mock_database):
        """Test CSV import with missing file."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key:
            mock_key.return_value = b"test_key" * 4
            
            result = cli_runner.invoke(cli, [
                'import-csv',
                '--file', '/nonexistent/file.csv'
            ])
            
            assert result.exit_code != 0
    
    def test_import_csv_invalid_format(self, cli_runner, test_db):
        """Test CSV import with invalid format."""
        # Create CSV with missing required columns
        csv_content = "website,user\ntest.com,user123"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(csv_content)
            temp_path = f.name
        
        try:
            with patch('src.cli.credstor.get_encryption_key') as mock_key:
                mock_key.return_value = b"test_key" * 4
                
                result = cli_runner.invoke(cli, [
                    'import-csv',
                    '--file', temp_path,
                    '--dry-run'
                ])
                
                assert result.exit_code == 0
                assert "Missing required fields" in result.output
        
        finally:
            os.unlink(temp_path)


@pytest.mark.cli
class TestShowCommand:
    """Test credential show command."""
    
    def test_show_credential_without_secrets(self, cli_runner, mock_config, mock_database):
        """Test showing credential without decrypted secrets."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key:
            mock_key.return_value = b"test_key" * 4
            
            mock_credential = MagicMock()
            mock_credential.id = "12345678-1234-1234-1234-123456789012"
            mock_credential.property = "test.com"
            mock_credential.username = "testuser"
            mock_credential.created_at = "2023-01-01T00:00:00"
            mock_credential.updated_at = "2023-01-01T00:00:00"
            mock_credential.last_accessed = None
            
            mock_query = mock_database.query.return_value
            mock_query.filter.return_value = mock_query
            mock_query.first.return_value = mock_credential
            
            result = cli_runner.invoke(cli, [
                'show', '12345678-1234-1234-1234-123456789012'
            ])
            
            assert result.exit_code == 0
            assert "test.com" in result.output
            assert "testuser" in result.output
            assert "Use --show-secrets to display" in result.output
    
    def test_show_credential_not_found(self, cli_runner, mock_config, mock_database):
        """Test showing non-existent credential."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key:
            mock_key.return_value = b"test_key" * 4
            
            mock_query = mock_database.query.return_value
            mock_query.filter.return_value = mock_query
            mock_query.first.return_value = None
            
            result = cli_runner.invoke(cli, [
                'show', '12345678-1234-1234-1234-123456789012'
            ])
            
            assert result.exit_code == 0
            assert "Credential not found" in result.output


@pytest.mark.cli
class TestDeleteCommand:
    """Test credential deletion command."""
    
    def test_delete_credential_confirmed(self, cli_runner, mock_config, mock_database):
        """Test deleting credential with confirmation."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key, \
             patch('src.cli.credstor.Confirm.ask') as mock_confirm:
            
            mock_key.return_value = b"test_key" * 4
            mock_confirm.return_value = True
            
            mock_credential = MagicMock()
            mock_credential.property = "test.com"
            mock_credential.username = "testuser"
            mock_credential.is_active = True
            
            mock_query = mock_database.query.return_value
            mock_query.filter.return_value = mock_query
            mock_query.first.return_value = mock_credential
            
            result = cli_runner.invoke(cli, [
                'delete', '12345678-1234-1234-1234-123456789012'
            ])
            
            assert result.exit_code == 0
            assert "Credential deleted successfully" in result.output
            assert mock_credential.is_active is False
    
    def test_delete_credential_cancelled(self, cli_runner, mock_config, mock_database):
        """Test deleting credential with cancellation."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key, \
             patch('src.cli.credstor.Confirm.ask') as mock_confirm:
            
            mock_key.return_value = b"test_key" * 4
            mock_confirm.return_value = False
            
            mock_credential = MagicMock()
            mock_credential.property = "test.com"
            mock_credential.username = "testuser"
            
            mock_query = mock_database.query.return_value
            mock_query.filter.return_value = mock_query
            mock_query.first.return_value = mock_credential
            
            result = cli_runner.invoke(cli, [
                'delete', '12345678-1234-1234-1234-123456789012'
            ])
            
            assert result.exit_code == 0
            assert "Deletion cancelled" in result.output