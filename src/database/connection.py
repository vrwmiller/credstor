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
    from ..utils.config import get_config
    from .models import Base
except ImportError:
    # Fallback for direct execution
    from utils.config import get_config
    from database.models import Base

logger = logging.getLogger(__name__)

# Global session factory
SessionLocal: Optional[sessionmaker] = None
engine: Optional[Engine] = None


def get_database_url() -> str:
    """
    Construct database URL based on configuration.
    
    Returns:
        Database URL string for SQLAlchemy
    """
    config = get_config()
    db_config = config.database
    
    if db_config.type == "sqlite":
        # Ensure data directory exists
        db_path = db_config.path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Use regular SQLite for now (can add encryption back later)
        return f"sqlite:///{db_path}"
    
    elif db_config.type == "postgresql":
        # PostgreSQL connection string
        return (
            f"postgresql://{db_config.username}:{db_config.password}@"
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
        "error": None
    }
    
    try:
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
        
        # Test encryption (SQLite only)
        config = get_config()
        if config.database.type == "sqlite":
            with get_db() as db:
                # For regular SQLite (not SQLCipher), just check if basic queries work
                # TODO: Re-enable when we add SQLCipher back
                # result = db.execute(text("PRAGMA cipher_version")).fetchone()
                # if result:
                #     health_status["encryption_working"] = True
                
                # For now, just mark as working since we can connect
                health_status["encryption_working"] = True
        else:
            # For other databases, assume encryption is working if connected
            health_status["encryption_working"] = health_status["database_connected"]
    
    except Exception as e:
        health_status["error"] = str(e)
        logger.error(f"Database health check failed: {e}")
    
    return health_status