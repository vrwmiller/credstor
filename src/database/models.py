"""
Database models for CredStor.

This module defines the SQLAlchemy models for storing encrypted credentials
and related data in the database.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, String, Text, DateTime, LargeBinary, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()


class Credential(Base):
    """
    Main credential storage model.
    
    All sensitive fields (password, api_token, public_key, private_key)
    are encrypted before storage using AES-256-GCM.
    """
    
    __tablename__ = "credentials"
    
    # Primary key - UUID for security
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False
    )
    
    # Basic credential information
    property = Column(String(255), nullable=False, index=True)  # Website/service name
    username = Column(String(255), nullable=False)  # Login username
    
    # Encrypted sensitive fields
    password_encrypted = Column(LargeBinary, nullable=True)  # Encrypted password
    api_token_encrypted = Column(LargeBinary, nullable=True)  # Encrypted API token
    public_key_encrypted = Column(LargeBinary, nullable=True)  # Encrypted public key
    private_key_encrypted = Column(LargeBinary, nullable=True)  # Encrypted private key
    
    # Optional fields
    notes_encrypted = Column(LargeBinary, nullable=True)  # Encrypted notes
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    last_accessed = Column(DateTime(timezone=True), nullable=True)
    
    # Security metadata
    encryption_version = Column(String(10), default="1.0", nullable=False)  # For key rotation
    is_active = Column(Boolean, default=True, nullable=False)  # Soft delete
    
    def __repr__(self) -> str:
        """String representation (safe - no sensitive data)."""
        return f"<Credential(id={self.id}, property='{self.property}', username='{self.username}')>"


class AuditLog(Base):
    """
    Audit log for security events and credential access.
    
    This table stores all security-relevant events without exposing
    sensitive credential data.
    """
    
    __tablename__ = "audit_logs"
    
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False
    )
    
    # Event information
    event_type = Column(String(50), nullable=False, index=True)  # CREATE, READ, UPDATE, DELETE, AUTH
    event_description = Column(String(255), nullable=False)
    
    # Related credential (if applicable)
    credential_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    
    # Security context
    user_agent = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    client_cert_fingerprint = Column(String(128), nullable=True)
    
    # Result
    success = Column(Boolean, nullable=False)
    error_message = Column(String(255), nullable=True)
    
    # Timing
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    
    def __repr__(self) -> str:
        """String representation."""
        return f"<AuditLog(id={self.id}, event_type='{self.event_type}', success={self.success})>"


class SecurityEvent(Base):
    """
    Security events table for authentication and authorization events.
    """
    
    __tablename__ = "security_events"
    
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False
    )
    
    # Event classification
    event_category = Column(String(50), nullable=False, index=True)  # AUTH, CRYPTO, ACCESS, etc.
    severity = Column(String(20), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Event details
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Security context
    source_ip = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    session_id = Column(String(128), nullable=True)
    
    # Timing and resolution
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    resolved = Column(Boolean, default=False, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    
    def __repr__(self) -> str:
        """String representation."""
        return f"<SecurityEvent(id={self.id}, category='{self.event_category}', severity='{self.severity}')>"


class EncryptionKey(Base):
    """
    Encryption key metadata for key rotation and management.
    
    Note: This table stores metadata about encryption keys, not the keys themselves.
    Actual encryption keys are derived from the master password and stored configuration.
    """
    
    __tablename__ = "encryption_keys"
    
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False
    )
    
    # Key identification
    key_version = Column(String(10), nullable=False, unique=True, index=True)
    algorithm = Column(String(50), nullable=False)  # AES-256-GCM, etc.
    
    # Key lifecycle
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    activated_at = Column(DateTime(timezone=True), nullable=True)
    deactivated_at = Column(DateTime(timezone=True), nullable=True)
    
    # Status
    is_active = Column(Boolean, default=False, nullable=False)
    is_primary = Column(Boolean, default=False, nullable=False)  # Primary key for new encryptions
    
    # Usage statistics
    records_encrypted = Column(String(255), default="0", nullable=False)  # Count of records using this key
    
    def __repr__(self) -> str:
        """String representation."""
        return f"<EncryptionKey(version='{self.key_version}', algorithm='{self.algorithm}', active={self.is_active})>"