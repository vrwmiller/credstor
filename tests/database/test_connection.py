"""
Tests for database connection and management.
"""

import pytest
import tempfile
import os
from pathlib import Path
from sqlalchemy import text

from src.database.connection import (
    init_database, get_database_session, get_db, close_database,
    check_database_health, get_database_url
)
from src.utils.config import Config, DatabaseConfig


@pytest.mark.database
class TestDatabaseConnection:
    """Test database connection functionality."""
    
    def test_get_database_url_sqlite(self, test_config):
        """Test SQLite database URL generation."""
        # Temporarily set config
        import src.utils.config as config_module
        original_config = config_module._config
        config_module._config = test_config
        
        try:
            url = get_database_url()
            assert "sqlite:///" in url
            assert test_config.database.path in url
        finally:
            config_module._config = original_config
    
    def test_database_initialization(self, test_db):
        """Test database initialization."""
        # Database should be initialized by the test_db fixture
        health = check_database_health()
        
        assert health["database_connected"] is True
        assert health["tables_exist"] is True
    
    def test_database_session_context_manager(self, test_db):
        """Test database session context manager."""
        with get_db() as db:
            # Should be able to execute a simple query
            result = db.execute(text("SELECT 1")).scalar()
            assert result == 1
    
    def test_database_health_check(self, test_db):
        """Test database health check functionality."""
        health = check_database_health()
        
        assert isinstance(health, dict)
        assert "database_connected" in health
        assert "tables_exist" in health
        assert "encryption_working" in health
        
        # For a properly initialized test database
        assert health["database_connected"] is True
        assert health["tables_exist"] is True


@pytest.mark.database
class TestDatabaseError:
    """Test database error handling."""
    
    def test_session_without_initialization(self):
        """Test that getting session without initialization raises error."""
        # Close any existing database connection
        close_database()
        
        with pytest.raises(RuntimeError, match="Database not initialized"):
            get_database_session()
    
    def test_invalid_database_path(self):
        """Test handling of invalid database path."""
        # Create a config with invalid database path
        invalid_config = Config(
            database=DatabaseConfig(
                type="sqlite",
                path="/invalid/path/that/does/not/exist/db.sqlite",
                encryption_key="dGVzdF9rZXlfMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A="  # Base64 test key
            )
        )
        
        # Temporarily set config
        import src.utils.config as config_module
        original_config = config_module._config
        config_module._config = invalid_config
        
        try:
            # This should raise an exception due to invalid path
            with pytest.raises(Exception):
                init_database()
        finally:
            config_module._config = original_config
            close_database()


@pytest.mark.integration
class TestDatabaseIntegration:
    """Integration tests for database operations."""
    
    def test_full_database_lifecycle(self, test_config):
        """Test complete database initialization, usage, and cleanup."""
        # Set up temporary database
        temp_dir = tempfile.mkdtemp()
        test_db_path = os.path.join(temp_dir, "test_integration.db")
        
        # Create modified config
        integration_config = Config(
            database=DatabaseConfig(
                type="sqlite",
                path=test_db_path,
                encryption_key=test_config.database.encryption_key,
                echo=False
            )
        )
        
        # Set config
        import src.utils.config as config_module
        original_config = config_module._config
        config_module._config = integration_config
        
        try:
            # Initialize database
            init_database()
            
            # Test connectivity
            with get_db() as db:
                result = db.execute(text("SELECT 1")).scalar()
                assert result == 1
            
            # Test health check
            health = check_database_health()
            assert health["database_connected"] is True
            
            # Cleanup
            close_database()
            
        finally:
            config_module._config = original_config
            # Clean up temporary files
            if os.path.exists(test_db_path):
                os.remove(test_db_path)
            os.rmdir(temp_dir)