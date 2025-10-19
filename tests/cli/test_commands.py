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
        
        # Mock CSV import configuration
        mock_config_obj.csv_import.default_encoding = "utf-8"
        mock_config_obj.csv_import.default_separator = ","
        mock_config_obj.csv_import.skip_empty_rows = True
        mock_config_obj.csv_import.validate_fields = True
        mock_config_obj.csv_import.field_mappings = {
            "property": "property",
            "username": "username", 
            "password": "password"
        }
        
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
    
    def test_import_csv_dry_run(self, cli_runner, mock_config, mock_database):
        """Test CSV import with dry run."""
        # Create temporary CSV file
        csv_content = "property,username,password\ntest.com,user,pass123\nexample.com,admin,secret456"
        
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
    
    def test_import_csv_invalid_format(self, cli_runner, mock_config, mock_database):
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


@pytest.mark.cli
class TestDatabaseCommands:
    """Test database management commands."""
    
    def test_db_migrate_no_pending(self, cli_runner, mock_config, mock_database):
        """Test database migration with no pending migrations."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key:
            mock_key.return_value = b"test_key" * 4
            
            with patch('src.database.migrations.migration_manager') as mock_manager:
                mock_manager.get_migration_status.return_value = {
                    "integrity_valid": True,
                    "pending_count": 0,
                    "database_type": "sqlite"
                }
                
                result = cli_runner.invoke(cli, ['db', 'migrate'])
                
                assert result.exit_code == 0
                assert "Database is up to date" in result.output
    
    def test_db_migrate_with_pending(self, cli_runner, mock_config, mock_database):
        """Test database migration with pending migrations."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key, \
             patch('src.cli.credstor.Confirm.ask') as mock_confirm:
            
            mock_key.return_value = b"test_key" * 4
            mock_confirm.return_value = True
            
            with patch('src.database.migrations.migration_manager') as mock_manager:
                mock_migration = MagicMock()
                mock_migration.version = "002"
                mock_migration.description = "Test migration"
                
                mock_manager.get_migration_status.return_value = {
                    "integrity_valid": True,
                    "pending_count": 1,
                    "database_type": "sqlite"
                }
                mock_manager.get_pending_migrations.return_value = [mock_migration]
                mock_manager.migrate.return_value = True
                
                result = cli_runner.invoke(cli, ['db', 'migrate'])
                
                assert result.exit_code == 0
                assert "Found 1 pending migrations" in result.output
                assert "All migrations applied successfully" in result.output
    
    def test_db_migrate_dry_run(self, cli_runner, mock_config, mock_database):
        """Test database migration dry run."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key:
            mock_key.return_value = b"test_key" * 4
            
            with patch('src.database.migrations.migration_manager') as mock_manager:
                mock_migration = MagicMock()
                mock_migration.version = "002"
                mock_migration.description = "Test migration"
                
                mock_manager.get_migration_status.return_value = {
                    "integrity_valid": True,
                    "pending_count": 1,
                    "database_type": "sqlite"
                }
                mock_manager.get_pending_migrations.return_value = [mock_migration]
                
                result = cli_runner.invoke(cli, ['db', 'migrate', '--dry-run'])
                
                assert result.exit_code == 0
                assert "Dry run complete - no changes made" in result.output
    
    def test_db_status(self, cli_runner, mock_config, mock_database):
        """Test database migration status command."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key:
            mock_key.return_value = b"test_key" * 4
            
            with patch('src.database.migrations.migration_manager') as mock_manager:
                mock_manager.get_migration_status.return_value = {
                    "database_type": "sqlite",
                    "applied_count": 2,
                    "pending_count": 1,
                    "integrity_valid": True,
                    "applied_versions": ["001", "002"],
                    "pending_versions": ["003"]
                }
                
                result = cli_runner.invoke(cli, ['db', 'status'])
                
                assert result.exit_code == 0
                assert "Database Migration Status" in result.output
                assert "sqlite" in result.output
                assert "Applied Migrations" in result.output
                assert "Pending Migrations" in result.output
    
    def test_db_backup(self, cli_runner, mock_config, mock_database):
        """Test database backup command."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key, \
             patch('src.cli.credstor.decrypt_credential_fields') as mock_decrypt, \
             patch('builtins.open', create=True) as mock_open, \
             patch('os.chmod') as mock_chmod:
            
            mock_key.return_value = b"test_key" * 4
            mock_decrypt.return_value = {
                "id": "12345678-1234-1234-1234-123456789012",
                "property": "test.com",
                "username": "testuser",
                "password": "testpass"
            }
            
            # Mock credentials query
            mock_credential = MagicMock()
            mock_query = mock_database.query.return_value
            mock_query.filter.return_value = mock_query
            mock_query.all.return_value = [mock_credential]
            
            # Mock audit logs query
            mock_query.order_by.return_value = mock_query
            mock_query.limit.return_value = mock_query
            
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                result = cli_runner.invoke(cli, ['db', 'backup', '--file', temp_file.name])
                
                assert result.exit_code == 0
                assert "Backup created successfully" in result.output
                
                # Cleanup
                os.unlink(temp_file.name)
    
    def test_db_stats(self, cli_runner, mock_config, mock_database):
        """Test database statistics command."""
        with patch('src.cli.credstor.get_encryption_key') as mock_key:
            mock_key.return_value = b"test_key" * 4
            
            # Mock database queries
            mock_database.query.return_value.count.return_value = 10
            mock_database.query.return_value.filter.return_value.count.return_value = 8
            mock_database.execute.return_value.fetchall.return_value = [
                ("CREATE", 5),
                ("READ", 3),
                ("DELETE", 1)
            ]
            
            result = cli_runner.invoke(cli, ['db', 'stats'])
            
            assert result.exit_code == 0
            assert "Database Statistics" in result.output
            assert "Total Credentials" in result.output
            assert "Active Credentials" in result.output


@pytest.mark.cli
class TestInitAuthCommand:
    """Test database authentication initialization command."""
    
    def test_init_auth_new_setup(self, cli_runner):
        """Test initializing new database authentication."""
        with patch('src.cli.credstor.verify_database_authentication') as mock_verify, \
             patch('src.cli.credstor.Prompt.ask') as mock_prompt, \
             patch('src.cli.credstor.getpass') as mock_getpass, \
             patch('src.cli.credstor.create_database_credentials') as mock_create:
            
            mock_verify.return_value = False
            mock_prompt.return_value = "testuser"
            mock_getpass.return_value = "testpass"
            
            result = cli_runner.invoke(cli, ['init-auth'])
            
            assert result.exit_code == 0
            assert "Database authentication configured successfully" in result.output
            mock_create.assert_called_once_with("testuser", "testpass")
    
    def test_init_auth_update_existing(self, cli_runner):
        """Test updating existing database authentication."""
        with patch('src.cli.credstor.verify_database_authentication') as mock_verify, \
             patch('src.cli.credstor.Confirm.ask') as mock_confirm, \
             patch('src.cli.credstor.Prompt.ask') as mock_prompt, \
             patch('src.cli.credstor.getpass') as mock_getpass, \
             patch('src.cli.credstor.create_database_credentials') as mock_create:
            
            mock_verify.return_value = True
            mock_confirm.return_value = True
            mock_prompt.return_value = "newuser"
            mock_getpass.return_value = "newpass"
            
            result = cli_runner.invoke(cli, ['init-auth'])
            
            assert result.exit_code == 0
            assert "Database authentication configured successfully" in result.output
            mock_create.assert_called_once_with("newuser", "newpass")
    
    def test_init_auth_cancel_update(self, cli_runner):
        """Test cancelling database authentication update."""
        with patch('src.cli.credstor.verify_database_authentication') as mock_verify, \
             patch('src.cli.credstor.Confirm.ask') as mock_confirm:
            
            mock_verify.return_value = True
            mock_confirm.return_value = False
            
            result = cli_runner.invoke(cli, ['init-auth'])
            
            assert result.exit_code == 0
            assert "Authentication setup cancelled" in result.output