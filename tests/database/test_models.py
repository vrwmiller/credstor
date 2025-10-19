"""
Tests for database models and operations.
"""

import pytest
import uuid
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError

from src.database.models import Credential, AuditLog, SecurityEvent, EncryptionKey
from src.database.connection import get_db


@pytest.mark.database
class TestCredentialModel:
    """Test credential model operations."""
    
    def test_create_credential(self, test_db):
        """Test creating a new credential."""
        with get_db() as db:
            credential = Credential(
                property="test.com",
                username="testuser",
                password_encrypted=b"encrypted_password",
                api_token_encrypted=b"encrypted_token"
            )
            
            db.add(credential)
            db.commit()
            db.refresh(credential)
            
            assert credential.id is not None
            assert isinstance(credential.id, uuid.UUID)
            assert credential.property == "test.com"
            assert credential.username == "testuser"
            assert credential.is_active is True
            assert credential.created_at is not None
            assert credential.updated_at is not None
    
    def test_credential_repr(self, test_db):
        """Test credential string representation."""
        credential = Credential(
            property="test.com",
            username="testuser"
        )
        
        repr_str = repr(credential)
        assert "test.com" in repr_str
        assert "testuser" in repr_str
        assert "Credential" in repr_str
    
    def test_soft_delete(self, test_db):
        """Test soft delete functionality."""
        with get_db() as db:
            credential = Credential(
                property="test.com",
                username="testuser",
                password_encrypted=b"encrypted_password"
            )
            
            db.add(credential)
            db.commit()
            db.refresh(credential)
            
            # Soft delete
            credential.is_active = False
            db.commit()
            
            # Verify it's still in database but marked inactive
            inactive_cred = db.query(Credential).filter(
                Credential.id == credential.id
            ).first()
            
            assert inactive_cred is not None
            assert inactive_cred.is_active is False
    
    def test_query_active_only(self, test_db):
        """Test querying only active credentials."""
        with get_db() as db:
            # Create active credential
            active_cred = Credential(
                property="active.com",
                username="activeuser",
                password_encrypted=b"encrypted_password"
            )
            
            # Create inactive credential
            inactive_cred = Credential(
                property="inactive.com",
                username="inactiveuser",
                password_encrypted=b"encrypted_password",
                is_active=False
            )
            
            db.add_all([active_cred, inactive_cred])
            db.commit()
            
            # Query only active credentials
            active_only = db.query(Credential).filter(
                Credential.is_active == True
            ).all()
            
            assert len(active_only) == 1
            assert active_only[0].property == "active.com"


@pytest.mark.database
class TestAuditLogModel:
    """Test audit log model operations."""
    
    def test_create_audit_log(self, test_db):
        """Test creating an audit log entry."""
        with get_db() as db:
            audit_log = AuditLog(
                event_type="CREATE",
                event_description="Created new credential",
                credential_id=uuid.uuid4(),
                success=True,
                ip_address="127.0.0.1"
            )
            
            db.add(audit_log)
            db.commit()
            db.refresh(audit_log)
            
            assert audit_log.id is not None
            assert audit_log.event_type == "CREATE"
            assert audit_log.success is True
            assert audit_log.timestamp is not None
    
    def test_audit_log_repr(self, test_db):
        """Test audit log string representation."""
        audit_log = AuditLog(
            event_type="READ",
            event_description="Viewed credential",
            success=True
        )
        
        repr_str = repr(audit_log)
        assert "READ" in repr_str
        assert "AuditLog" in repr_str


@pytest.mark.database
class TestSecurityEventModel:
    """Test security event model operations."""
    
    def test_create_security_event(self, test_db):
        """Test creating a security event."""
        with get_db() as db:
            security_event = SecurityEvent(
                event_category="AUTH",
                severity="HIGH",
                title="Failed login attempt",
                description="Multiple failed login attempts detected",
                source_ip="192.168.1.100"
            )
            
            db.add(security_event)
            db.commit()
            db.refresh(security_event)
            
            assert security_event.id is not None
            assert security_event.event_category == "AUTH"
            assert security_event.severity == "HIGH"
            assert security_event.resolved is False
            assert security_event.timestamp is not None
    
    def test_resolve_security_event(self, test_db):
        """Test resolving a security event."""
        with get_db() as db:
            security_event = SecurityEvent(
                event_category="AUTH",
                severity="MEDIUM",
                title="Suspicious activity",
                description="Unusual login pattern detected"
            )
            
            db.add(security_event)
            db.commit()
            db.refresh(security_event)
            
            # Resolve the event
            security_event.resolved = True
            security_event.resolved_at = datetime.now(timezone.utc)
            db.commit()
            
            assert security_event.resolved is True
            assert security_event.resolved_at is not None


@pytest.mark.database
class TestEncryptionKeyModel:
    """Test encryption key model operations."""
    
    def test_create_encryption_key(self, test_db):
        """Test creating an encryption key record."""
        with get_db() as db:
            encryption_key = EncryptionKey(
                key_version="1.0",
                algorithm="AES-256-GCM",
                is_active=True,
                is_primary=True,
                records_encrypted="100"
            )
            
            db.add(encryption_key)
            db.commit()
            db.refresh(encryption_key)
            
            assert encryption_key.id is not None
            assert encryption_key.key_version == "1.0"
            assert encryption_key.algorithm == "AES-256-GCM"
            assert encryption_key.is_active is True
            assert encryption_key.is_primary is True
    
    def test_unique_key_version(self, test_db):
        """Test that key versions must be unique."""
        with get_db() as db:
            key1 = EncryptionKey(
                key_version="1.0",
                algorithm="AES-256-GCM"
            )
            
            key2 = EncryptionKey(
                key_version="1.0",  # Same version
                algorithm="AES-256-GCM"
            )
            
            db.add(key1)
            db.commit()
            
            db.add(key2)
            with pytest.raises(IntegrityError):
                db.commit()