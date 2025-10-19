"""
Database migration system for CredStor.

This module provides functionality to manage database schema changes
across different versions of CredStor, ensuring smooth upgrades and
proper version control of database structure.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass
import hashlib

from sqlalchemy import text, MetaData, Table, Column, String, DateTime, Integer, Boolean
from sqlalchemy.exc import SQLAlchemyError

from .connection import get_db, create_database_engine
from ..utils.config import get_config

logger = logging.getLogger(__name__)


@dataclass
class Migration:
    """Represents a database migration."""
    version: str
    description: str
    up_sql: str
    down_sql: str
    checksum: str
    
    @classmethod
    def create(cls, version: str, description: str, up_sql: str, down_sql: str) -> 'Migration':
        """Create a migration with calculated checksum."""
        content = f"{version}{description}{up_sql}{down_sql}"
        checksum = hashlib.sha256(content.encode()).hexdigest()
        
        return cls(
            version=version,
            description=description,
            up_sql=up_sql,
            down_sql=down_sql,
            checksum=checksum
        )


class MigrationManager:
    """Manages database migrations for CredStor."""
    
    MIGRATION_TABLE = "credstor_migrations"
    
    def __init__(self):
        self.config = get_config()
        self.migrations: List[Migration] = []
        self._load_migrations()
    
    def _load_migrations(self):
        """Load all available migrations."""
        # Migration 001: Initial schema (already applied in connection.py)
        self.migrations.append(Migration.create(
            version="001",
            description="Initial schema with credentials, audit_log, security_events, encryption_keys",
            up_sql="-- Initial schema created by SQLAlchemy models",
            down_sql="DROP TABLE IF EXISTS encryption_keys, security_events, audit_log, credentials CASCADE;"
        ))
        
        # Migration 002: Add indexes for performance
        self.migrations.append(Migration.create(
            version="002", 
            description="Add indexes for frequently queried columns",
            up_sql="""
                CREATE INDEX IF NOT EXISTS idx_credentials_property ON credentials(property);
                CREATE INDEX IF NOT EXISTS idx_credentials_username ON credentials(username);
                CREATE INDEX IF NOT EXISTS idx_credentials_deleted ON credentials(deleted_at);
                CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
                CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
                CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_security_events_resolved ON security_events(resolved);
            """,
            down_sql="""
                DROP INDEX IF EXISTS idx_credentials_property;
                DROP INDEX IF EXISTS idx_credentials_username;
                DROP INDEX IF EXISTS idx_credentials_deleted;
                DROP INDEX IF EXISTS idx_audit_log_timestamp;
                DROP INDEX IF EXISTS idx_audit_log_action;
                DROP INDEX IF EXISTS idx_security_events_timestamp;
                DROP INDEX IF EXISTS idx_security_events_resolved;
            """
        ))
        
        # Migration 003: Add full-text search capabilities (PostgreSQL only)
        if self.config.database.type == "postgresql":
            self.migrations.append(Migration.create(
                version="003",
                description="Add full-text search capabilities for PostgreSQL",
                up_sql="""
                    ALTER TABLE credentials ADD COLUMN IF NOT EXISTS search_vector tsvector;
                    
                    CREATE OR REPLACE FUNCTION update_credentials_search_vector() RETURNS trigger AS $$
                    BEGIN
                        NEW.search_vector := to_tsvector('english', 
                            COALESCE(NEW.property, '') || ' ' ||
                            COALESCE(NEW.username, '') || ' ' ||
                            COALESCE(NEW.notes, '')
                        );
                        RETURN NEW;
                    END;
                    $$ LANGUAGE plpgsql;
                    
                    DROP TRIGGER IF EXISTS update_search_vector_trigger ON credentials;
                    CREATE TRIGGER update_search_vector_trigger
                        BEFORE INSERT OR UPDATE ON credentials
                        FOR EACH ROW EXECUTE FUNCTION update_credentials_search_vector();
                    
                    CREATE INDEX IF NOT EXISTS idx_credentials_search_vector 
                        ON credentials USING GIN(search_vector);
                    
                    -- Update existing records
                    UPDATE credentials SET search_vector = to_tsvector('english', 
                        COALESCE(property, '') || ' ' ||
                        COALESCE(username, '') || ' ' ||
                        COALESCE(notes, '')
                    );
                """,
                down_sql="""
                    DROP TRIGGER IF EXISTS update_search_vector_trigger ON credentials;
                    DROP FUNCTION IF EXISTS update_credentials_search_vector();
                    DROP INDEX IF EXISTS idx_credentials_search_vector;
                    ALTER TABLE credentials DROP COLUMN IF EXISTS search_vector;
                """
            ))
    
    def _ensure_migration_table(self):
        """Ensure the migration tracking table exists."""
        engine = create_database_engine()
        
        if self.config.database.type == "postgresql":
            create_sql = f"""
                CREATE TABLE IF NOT EXISTS {self.MIGRATION_TABLE} (
                    version VARCHAR(10) PRIMARY KEY,
                    description TEXT NOT NULL,
                    checksum VARCHAR(64) NOT NULL,
                    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    applied_by VARCHAR(100) DEFAULT CURRENT_USER
                );
            """
        else:  # SQLite
            create_sql = f"""
                CREATE TABLE IF NOT EXISTS {self.MIGRATION_TABLE} (
                    version TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    applied_by TEXT DEFAULT 'unknown'
                );
            """
        
        try:
            with engine.connect() as conn:
                conn.execute(text(create_sql))
                conn.commit()
                logger.info("Migration table ensured")
        except SQLAlchemyError as e:
            logger.error(f"Failed to create migration table: {e}")
            raise
    
    def get_applied_migrations(self) -> List[str]:
        """Get list of applied migration versions."""
        self._ensure_migration_table()
        
        try:
            with get_db() as session:
                result = session.execute(
                    text(f"SELECT version FROM {self.MIGRATION_TABLE} ORDER BY version")
                )
                return [row[0] for row in result.fetchall()]
        except SQLAlchemyError as e:
            logger.error(f"Failed to get applied migrations: {e}")
            return []
    
    def get_pending_migrations(self) -> List[Migration]:
        """Get list of pending migrations that need to be applied."""
        applied_versions = set(self.get_applied_migrations())
        return [m for m in self.migrations if m.version not in applied_versions]
    
    def validate_migration_integrity(self) -> bool:
        """Validate that applied migrations haven't been tampered with."""
        self._ensure_migration_table()
        
        try:
            with get_db() as session:
                result = session.execute(
                    text(f"SELECT version, checksum FROM {self.MIGRATION_TABLE}")
                )
                applied_checksums = {row[0]: row[1] for row in result.fetchall()}
            
            # Check that all applied migrations have matching checksums
            for migration in self.migrations:
                if migration.version in applied_checksums:
                    if applied_checksums[migration.version] != migration.checksum:
                        logger.error(
                            f"Migration {migration.version} checksum mismatch! "
                            f"Expected: {migration.checksum}, "
                            f"Found: {applied_checksums[migration.version]}"
                        )
                        return False
            
            logger.info("Migration integrity validation passed")
            return True
            
        except SQLAlchemyError as e:
            logger.error(f"Failed to validate migration integrity: {e}")
            return False
    
    def apply_migration(self, migration: Migration) -> bool:
        """Apply a single migration."""
        logger.info(f"Applying migration {migration.version}: {migration.description}")
        
        try:
            with get_db() as session:
                # Execute the migration SQL
                if migration.up_sql.strip() and not migration.up_sql.strip().startswith("--"):
                    # Split SQL statements and execute them individually
                    statements = [s.strip() for s in migration.up_sql.split(';') if s.strip()]
                    for statement in statements:
                        if statement:
                            session.execute(text(statement))
                
                # Record the migration as applied
                session.execute(
                    text(f"""
                        INSERT INTO {self.MIGRATION_TABLE} 
                        (version, description, checksum, applied_at) 
                        VALUES (:version, :description, :checksum, :applied_at)
                    """),
                    {
                        "version": migration.version,
                        "description": migration.description,
                        "checksum": migration.checksum,
                        "applied_at": datetime.utcnow()
                    }
                )
                
                session.commit()
                logger.info(f"Migration {migration.version} applied successfully")
                return True
                
        except SQLAlchemyError as e:
            logger.error(f"Failed to apply migration {migration.version}: {e}")
            return False
    
    def rollback_migration(self, version: str) -> bool:
        """Rollback a specific migration."""
        migration = next((m for m in self.migrations if m.version == version), None)
        if not migration:
            logger.error(f"Migration {version} not found")
            return False
        
        logger.warning(f"Rolling back migration {version}: {migration.description}")
        
        try:
            with get_db() as session:
                # Execute the rollback SQL
                if migration.down_sql.strip():
                    statements = [s.strip() for s in migration.down_sql.split(';') if s.strip()]
                    for statement in statements:
                        if statement:
                            session.execute(text(statement))
                
                # Remove the migration record
                session.execute(
                    text(f"DELETE FROM {self.MIGRATION_TABLE} WHERE version = :version"),
                    {"version": version}
                )
                
                session.commit()
                logger.info(f"Migration {version} rolled back successfully")
                return True
                
        except SQLAlchemyError as e:
            logger.error(f"Failed to rollback migration {version}: {e}")
            return False
    
    def migrate(self) -> bool:
        """Apply all pending migrations."""
        if not self.validate_migration_integrity():
            logger.error("Migration integrity check failed - aborting migration")
            return False
        
        pending = self.get_pending_migrations()
        if not pending:
            logger.info("No pending migrations")
            return True
        
        logger.info(f"Found {len(pending)} pending migrations")
        
        for migration in pending:
            if not self.apply_migration(migration):
                logger.error(f"Migration failed at version {migration.version}")
                return False
        
        logger.info("All migrations applied successfully")
        return True
    
    def get_migration_status(self) -> Dict[str, Any]:
        """Get current migration status."""
        applied = self.get_applied_migrations()
        pending = self.get_pending_migrations()
        
        return {
            "applied_count": len(applied),
            "pending_count": len(pending),
            "applied_versions": applied,
            "pending_versions": [m.version for m in pending],
            "integrity_valid": self.validate_migration_integrity(),
            "database_type": self.config.database.type
        }


# Global migration manager instance
migration_manager = MigrationManager()


def migrate_database() -> bool:
    """Convenience function to run migrations."""
    return migration_manager.migrate()


def get_migration_status() -> Dict[str, Any]:
    """Convenience function to get migration status."""
    return migration_manager.get_migration_status()


def rollback_migration(version: str) -> bool:
    """Convenience function to rollback a migration."""
    return migration_manager.rollback_migration(version)