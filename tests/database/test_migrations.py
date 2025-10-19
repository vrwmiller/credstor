"""
Tests for database migration system.
"""

import pytest
import tempfile
import os
from unittest.mock import patch, MagicMock

from src.database.migrations import Migration, MigrationManager, migrate_database, get_migration_status


@pytest.mark.database
class TestMigration:
    """Test Migration class."""
    
    def test_migration_creation(self):
        """Test creating a migration with checksum."""
        migration = Migration.create(
            version="001",
            description="Test migration",
            up_sql="CREATE TABLE test (id INTEGER);",
            down_sql="DROP TABLE test;"
        )
        
        assert migration.version == "001"
        assert migration.description == "Test migration"
        assert migration.up_sql == "CREATE TABLE test (id INTEGER);"
        assert migration.down_sql == "DROP TABLE test;"
        assert migration.checksum is not None
        assert len(migration.checksum) == 64  # SHA256 hex length
    
    def test_migration_checksum_consistency(self):
        """Test that same migration content produces same checksum."""
        migration1 = Migration.create(
            version="001",
            description="Test migration",
            up_sql="CREATE TABLE test (id INTEGER);",
            down_sql="DROP TABLE test;"
        )
        
        migration2 = Migration.create(
            version="001",
            description="Test migration",
            up_sql="CREATE TABLE test (id INTEGER);",
            down_sql="DROP TABLE test;"
        )
        
        assert migration1.checksum == migration2.checksum
    
    def test_migration_checksum_differs_on_content_change(self):
        """Test that different content produces different checksums."""
        migration1 = Migration.create(
            version="001",
            description="Test migration",
            up_sql="CREATE TABLE test (id INTEGER);",
            down_sql="DROP TABLE test;"
        )
        
        migration2 = Migration.create(
            version="001",
            description="Test migration",
            up_sql="CREATE TABLE test2 (id INTEGER);",  # Different SQL
            down_sql="DROP TABLE test;"
        )
        
        assert migration1.checksum != migration2.checksum


@pytest.mark.database
class TestMigrationManager:
    """Test MigrationManager class."""
    
    def test_manager_initialization(self):
        """Test that migration manager initializes with migrations."""
        manager = MigrationManager()
        
        assert len(manager.migrations) > 0
        assert any(m.version == "001" for m in manager.migrations)
        assert any(m.version == "002" for m in manager.migrations)
    
    def test_postgresql_specific_migrations(self):
        """Test that PostgreSQL-specific migrations are included for PostgreSQL."""
        with patch('src.database.migrations.get_config') as mock_config:
            mock_config.return_value.database.type = "postgresql"
            
            manager = MigrationManager()
            
            # Should include PostgreSQL-specific migration
            assert any(m.version == "003" for m in manager.migrations)
    
    def test_sqlite_excludes_postgresql_migrations(self):
        """Test that PostgreSQL-specific migrations are excluded for SQLite."""
        with patch('src.database.migrations.get_config') as mock_config:
            mock_config.return_value.database.type = "sqlite"
            
            manager = MigrationManager()
            
            # Should not include PostgreSQL-specific migration
            assert not any(m.version == "003" for m in manager.migrations)
    
    @patch('src.database.migrations.create_database_engine')
    def test_ensure_migration_table_postgresql(self, mock_engine):
        """Test migration table creation for PostgreSQL."""
        mock_conn = MagicMock()
        mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
        
        with patch('src.database.migrations.get_config') as mock_config:
            mock_config.return_value.database.type = "postgresql"
            
            manager = MigrationManager()
            manager._ensure_migration_table()
            
            mock_conn.execute.assert_called_once()
            sql_call = mock_conn.execute.call_args[0][0].text
            assert "CREATE TABLE IF NOT EXISTS" in sql_call
            assert "credstor_migrations" in sql_call
            assert "TIMESTAMP WITH TIME ZONE" in sql_call
    
    @patch('src.database.migrations.create_database_engine')
    def test_ensure_migration_table_sqlite(self, mock_engine):
        """Test migration table creation for SQLite."""
        mock_conn = MagicMock()
        mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
        
        with patch('src.database.migrations.get_config') as mock_config:
            mock_config.return_value.database.type = "sqlite"
            
            manager = MigrationManager()
            manager._ensure_migration_table()
            
            mock_conn.execute.assert_called_once()
            sql_call = mock_conn.execute.call_args[0][0].text
            assert "CREATE TABLE IF NOT EXISTS" in sql_call
            assert "credstor_migrations" in sql_call
            assert "DATETIME DEFAULT CURRENT_TIMESTAMP" in sql_call
    
    @patch('src.database.migrations.get_db')
    @patch('src.database.migrations.create_database_engine')
    def test_get_applied_migrations(self, mock_engine, mock_db):
        """Test getting list of applied migrations."""
        # Mock the engine and connection to prevent real database access
        mock_conn = MagicMock()
        mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
        
        mock_session = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_session
        
        # Mock database response
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [("001",), ("002",)]
        mock_session.execute.return_value = mock_result
        
        manager = MigrationManager()
        applied = manager.get_applied_migrations()
        
        assert applied == ["001", "002"]
    
    def test_get_pending_migrations(self):
        """Test getting list of pending migrations."""
        manager = MigrationManager()
        
        # Mock applied migrations
        with patch.object(manager, 'get_applied_migrations', return_value=["001"]):
            pending = manager.get_pending_migrations()
            
            # Should return migrations not in applied list
            pending_versions = [m.version for m in pending]
            assert "001" not in pending_versions
            assert "002" in pending_versions
    
    @patch('src.database.migrations.get_db')
    @patch('src.database.migrations.create_database_engine')
    def test_validate_migration_integrity_success(self, mock_engine, mock_db):
        """Test successful migration integrity validation."""
        # Mock the engine and connection to prevent real database access
        mock_conn = MagicMock()
        mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
        
        mock_session = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_session
        
        manager = MigrationManager()
        
        # Mock database response with correct checksums
        migration_001 = next(m for m in manager.migrations if m.version == "001")
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [("001", migration_001.checksum)]
        mock_session.execute.return_value = mock_result
        
        assert manager.validate_migration_integrity() is True
    
    @patch('src.database.migrations.get_db')
    @patch('src.database.migrations.create_database_engine')
    def test_validate_migration_integrity_failure(self, mock_engine, mock_db):
        """Test failed migration integrity validation."""
        # Mock the engine and connection to prevent real database access
        mock_conn = MagicMock()
        mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
        
        mock_session = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_session
        
        manager = MigrationManager()
        
        # Mock database response with incorrect checksum
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [("001", "wrong_checksum")]
        mock_session.execute.return_value = mock_result
        
        assert manager.validate_migration_integrity() is False
    
    @patch('src.database.migrations.get_db')
    def test_apply_migration_success(self, mock_db):
        """Test successful migration application."""
        mock_session = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_session
        
        manager = MigrationManager()
        migration = Migration.create(
            version="999",
            description="Test migration",
            up_sql="CREATE TABLE test (id INTEGER);",
            down_sql="DROP TABLE test;"
        )
        
        result = manager.apply_migration(migration)
        
        assert result is True
        assert mock_session.execute.call_count >= 2  # SQL + migration record
        mock_session.commit.assert_called()
    
    @patch('src.database.migrations.get_db')
    def test_apply_migration_skip_comments(self, mock_db):
        """Test that migrations with only comments are skipped."""
        mock_session = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_session
        
        manager = MigrationManager()
        migration = Migration.create(
            version="999",
            description="Test migration",
            up_sql="-- This is just a comment",
            down_sql="DROP TABLE test;"
        )
        
        result = manager.apply_migration(migration)
        
        assert result is True
        # Should only call execute once (for migration record, not for SQL)
        assert mock_session.execute.call_count == 1
    
    def test_get_migration_status(self):
        """Test getting migration status."""
        manager = MigrationManager()
        
        with patch.object(manager, 'get_applied_migrations', return_value=["001"]), \
             patch.object(manager, 'get_pending_migrations', return_value=[MagicMock(version="002")]), \
             patch.object(manager, 'validate_migration_integrity', return_value=True), \
             patch('src.database.migrations.get_config') as mock_config:
            
            mock_config.return_value.database.type = "postgresql"
            
            status = manager.get_migration_status()
            
            assert status["applied_count"] == 1
            assert status["pending_count"] == 1
            assert status["applied_versions"] == ["001"]
            assert status["pending_versions"] == ["002"]
            assert status["integrity_valid"] is True
            assert status["database_type"] == "postgresql"


@pytest.mark.database
class TestMigrationFunctions:
    """Test module-level migration functions."""
    
    @patch('src.database.migrations.migration_manager')
    def test_migrate_database(self, mock_manager):
        """Test migrate_database convenience function."""
        mock_manager.migrate.return_value = True
        
        result = migrate_database()
        
        assert result is True
        mock_manager.migrate.assert_called_once()
    
    @patch('src.database.migrations.migration_manager')
    def test_get_migration_status(self, mock_manager):
        """Test get_migration_status convenience function."""
        expected_status = {"test": "status"}
        mock_manager.get_migration_status.return_value = expected_status
        
        result = get_migration_status()
        
        assert result == expected_status
        mock_manager.get_migration_status.assert_called_once()


@pytest.mark.integration
class TestMigrationIntegration:
    """Integration tests for migration system."""
    
    def test_migration_manager_with_real_config(self, test_config):
        """Test migration manager with real configuration."""
        with patch('src.database.migrations.get_config', return_value=test_config):
            manager = MigrationManager()
            
            assert len(manager.migrations) >= 2
            assert manager.config.database.type == "sqlite"
            
            # Should not include PostgreSQL-specific migrations for SQLite
            postgresql_migrations = [m for m in manager.migrations if "PostgreSQL" in m.description]
            assert len(postgresql_migrations) == 0