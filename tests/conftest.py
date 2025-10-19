"""
Test configuration for CredStor tests.

This module provides common test fixtures and utilities.
"""

import pytest
import tempfile
import shutil
import base64
from pathlib import Path
from typing import Generator

from src.utils.config import Config, DatabaseConfig, SecurityConfig
from src.database.connection import init_database, close_database
from src.security.crypto import generate_salt, derive_key_from_password
from src.utils.user import get_current_username
from src.utils.user import get_current_username
import base64


@pytest.fixture
def test_config():
    """Configuration for testing."""
    # Create a unique temporary directory for each test
    temp_dir = tempfile.mkdtemp()
    username = get_current_username()
    test_password = "test_password_123"
    
    # Generate encryption key
    salt = generate_salt()
    key = derive_key_from_password(test_password, salt)
    key_b64 = base64.b64encode(key).decode('utf-8')
    
    # Use a unique filename with timestamp
    import time
    unique_id = str(int(time.time() * 1000000))  # Microsecond timestamp
    
    config = Config(
        database=DatabaseConfig(
            type="sqlite",
            path=f"{temp_dir}/test_credstor_{username}_{unique_id}.db",
            encryption_key=key_b64,
            echo=False
        ),
        security=SecurityConfig(
            master_password_required=False,  # Disable for tests
            client_cert_required=False,
            key_iterations=1000  # Faster for tests
        )
    )
    
    yield config
    
    # Cleanup
    try:
        shutil.rmtree(temp_dir)
    except:
        pass


@pytest.fixture
def test_db(test_config):
    """Initialize test database."""
    
    # Set global config for the test
    import src.utils.config as config_module
    original_config = config_module._config
    config_module._config = test_config
    
    try:
        # Initialize database
        init_database()
        
        yield
        
    finally:
        # Cleanup
        try:
            close_database()
        except:
            pass
        config_module._config = original_config


@pytest.fixture
def sample_credential_data():
    """Sample credential data for testing."""
    return {
        "property": "github.com",
        "username": "testuser",
        "password": "secret123",
        "api_token": "ghp_1234567890abcdef",
        "notes": "Test credential"
    }