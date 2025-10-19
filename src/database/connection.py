"""
Database connection and initialization for CredStor.

This module handles database connections, initialization, and provides
utility functions for database operations.
"""

import os
import logging
from typing import Optional
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

try:
    from ..utils.config import get_config, load_database_credentials, verify_database_authentication
    from .models import Base
except ImportError:
    # Fallback for direct execution
    from utils.config import get_config, load_database_credentials, verify_database_authentication
    from database.models import Base

logger = logging.getLogger(__name__)

# Global session factory
SessionLocal: Optional[sessionmaker] = None
engine: Optional[Engine] = None


def get_database_url() -> str:
    """
    Generate database connection URL with authentication.
    
    Returns:
        Database connection URL string
        
    Raises:
        ValueError: If database configuration is invalid
        FileNotFoundError: If database credentials are missing
        PermissionError: If credential file permissions are incorrect
    """
    config = get_config()
    db_config = config.database
    
    # Load database credentials from credstor.conf
    try:
        credentials = load_database_credentials()
    except Exception as e:
        logger.error(f"Failed to load database credentials: {e}")
        raise
    
    if db_config.type == "sqlite":
        # For SQLite, still require authentication but use file path
        if not credentials.is_valid():
            raise ValueError("Database authentication required: invalid credentials")
        
        # Ensure data directory exists
        db_path = db_config.path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Use regular SQLite with authentication verification
        logger.info(f"Database authentication verified for user: {credentials.username}")
        return f"sqlite:///{db_path}"
    
    elif db_config.type == "postgresql":
        # PostgreSQL connection using credentials from credstor.conf
        if not credentials.is_valid():
            raise ValueError("Database authentication required: invalid credentials")
            
        # Use credentials from credstor.conf with psycopg3 driver
        return (
            f"postgresql+psycopg://{credentials.username}:{credentials.password}@"
            f"{db_config.host}:{db_config.port}/{db_config.name}"
        )
    
    else:
        raise ValueError(f"Unsupported database type: {db_config.type}")


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """
    Set SQLite pragmas for security and performance.
    
    This function is called for every new database connection to ensure
    proper security settings are applied.
    """
    if 'sqlite' in str(dbapi_connection):
        cursor = dbapi_connection.cursor()
        
        # Security pragmas
        cursor.execute("PRAGMA foreign_keys=ON")  # Enforce foreign key constraints
        cursor.execute("PRAGMA secure_delete=ON")  # Securely delete data
        cursor.execute("PRAGMA auto_vacuum=FULL")  # Automatic database cleanup
        
        # Performance pragmas
        cursor.execute("PRAGMA cache_size=10000")  # 10MB cache
        cursor.execute("PRAGMA temp_store=MEMORY")  # Store temp data in memory
        cursor.execute("PRAGMA mmap_size=268435456")  # 256MB memory mapping
        
        # Journal mode for better concurrency
        cursor.execute("PRAGMA journal_mode=WAL")
        
        cursor.close()
        logger.debug("SQLite pragmas set for new connection")


def create_database_engine() -> Engine:
    """
    Create and configure database engine.
    
    Returns:
        Configured SQLAlchemy engine
    """
    config = get_config()
    db_config = config.database
    
    database_url = get_database_url()
    
    # Engine configuration
    engine_kwargs = {
        "echo": db_config.echo,
        "pool_pre_ping": True,  # Validate connections before use
    }
    
    # SQLite-specific configuration
    if db_config.type == "sqlite":
        engine_kwargs.update({
            "poolclass": StaticPool,
            "connect_args": {
                "check_same_thread": False,  # Allow multi-threading
                "timeout": 30,  # Connection timeout
            }
        })
    
    # PostgreSQL-specific configuration
    elif db_config.type == "postgresql":
        engine_kwargs.update({
            "pool_size": db_config.pool_size,
            "max_overflow": db_config.max_overflow,
            "pool_timeout": 30,
            "pool_recycle": 3600,  # Recycle connections every hour
        })
    
    engine = create_engine(database_url, **engine_kwargs)
    logger.info(f"Database engine created for {db_config.type}")
    
    return engine


def init_database() -> None:
    """
    Initialize database connection and create tables.
    
    This function should be called once during application startup.
    """
    global engine, SessionLocal
    
    try:
        # Create engine
        engine = create_database_engine()
        
        # Test connection
        with engine.connect() as conn:
            logger.info("Database connection established successfully")
        
        # Create all tables
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created/verified")
        
        # Create session factory
        SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=engine
        )
        
        # Run database migrations
        try:
            from .migrations import migration_manager
            logger.info("Running database migrations...")
            
            if migration_manager.migrate():
                logger.info("Database migrations completed successfully")
            else:
                logger.warning("Some database migrations failed - check logs")
        except ImportError:
            logger.debug("Migration system not available")
        except Exception as e:
            logger.warning(f"Migration system error: {e}")
        
        logger.info("Database initialization completed")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise


def get_database_session() -> Session:
    """
    Get a database session.
    
    Returns:
        SQLAlchemy session instance
        
    Raises:
        RuntimeError: If database is not initialized
    """
    if SessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    
    return SessionLocal()


@contextmanager
def get_db():
    """
    Context manager for database sessions.
    
    Yields:
        Database session with automatic cleanup
        
    Example:
        with get_db() as db:
            credential = db.query(Credential).first()
    """
    db = get_database_session()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def close_database() -> None:
    """
    Close database connections and clean up resources.
    
    This function should be called during application shutdown.
    """
    global engine, SessionLocal
    
    if engine:
        engine.dispose()
        engine = None
        logger.info("Database engine disposed")
    
    if SessionLocal:
        SessionLocal = None
        logger.info("Session factory cleared")


def check_database_health() -> dict:
    """
    Check database connectivity and health.
    
    Returns:
        Dictionary with health check results
    """
    health_status = {
        "database_connected": False,
        "tables_exist": False,
        "encryption_working": False,
        "authentication_working": False,
        "error": None
    }
    
    try:
        # Test database authentication first
        try:
            health_status["authentication_working"] = verify_database_authentication()
        except Exception as e:
            logger.warning(f"Authentication check failed: {e}")
            health_status["authentication_working"] = False
        
        # Test basic connectivity
        from sqlalchemy import text
        with get_db() as db:
            db.execute(text("SELECT 1"))
            health_status["database_connected"] = True
        
        # Check if tables exist
        if engine:
            from .models import Credential
            from sqlalchemy import inspect
            
            inspector = inspect(engine)
            tables = inspector.get_table_names()
            
            if "credentials" in tables:
                health_status["tables_exist"] = True
        
        # Test application-level encryption (database-agnostic)
        config = get_config()
        # If we can connect and have valid config, encryption should work
        if health_status["database_connected"]:
            try:
                # Test if we can load encryption key from config
                try:
                    from ..security.crypto import get_encryption_key_from_config
                except ImportError:
                    from security.crypto import get_encryption_key_from_config
                get_encryption_key_from_config()
                health_status["encryption_working"] = True
            except Exception as e:
                logger.warning(f"Encryption test failed: {e}")
                health_status["encryption_working"] = False
    
    except Exception as e:
        health_status["error"] = str(e)
        logger.error(f"Database health check failed: {e}")
    
    return health_status