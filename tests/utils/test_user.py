"""
Tests for user utility functions.
"""

import pytest
import os
import platform
from pathlib import Path

from src.utils.user import (
    get_current_username, get_user_home_dir, get_user_config_dir,
    get_user_data_dir, expand_user_path, get_system_info
)


@pytest.mark.unit
class TestUserUtilities:
    """Test user utility functions."""
    
    def test_get_current_username(self):
        """Test getting current username."""
        username = get_current_username()
        
        assert isinstance(username, str)
        assert len(username) > 0
        assert username != ""
        
        # Should match environment variable if available
        env_user = os.getenv('USER') or os.getenv('USERNAME')
        if env_user:
            assert username == env_user
    
    def test_get_user_home_dir(self):
        """Test getting user home directory."""
        home_dir = get_user_home_dir()
        
        assert isinstance(home_dir, Path)
        assert home_dir.exists()
        assert home_dir.is_dir()
        
        # Should match Path.home()
        assert home_dir == Path.home()
    
    def test_get_user_config_dir(self):
        """Test getting user config directory."""
        config_dir = get_user_config_dir()
        
        assert isinstance(config_dir, Path)
        assert "credstor" in str(config_dir).lower() or "CredStor" in str(config_dir)
        
        # Should be platform-appropriate
        system = platform.system()
        if system == "Darwin":  # macOS
            assert "Library/Application Support" in str(config_dir)
        elif system == "Windows":
            assert "AppData" in str(config_dir) or "APPDATA" in str(config_dir)
        else:  # Linux/Unix
            assert ".config" in str(config_dir) or "XDG_CONFIG_HOME" in os.environ
    
    def test_get_user_data_dir(self):
        """Test getting user data directory."""
        data_dir = get_user_data_dir()
        
        assert isinstance(data_dir, Path)
        assert "credstor" in str(data_dir).lower() or "CredStor" in str(data_dir)
        
        # Should be platform-appropriate
        system = platform.system()
        if system == "Darwin":  # macOS
            assert "Library/Application Support" in str(data_dir)
        elif system == "Windows":
            assert "AppData" in str(data_dir)
        else:  # Linux/Unix
            assert ".local/share" in str(data_dir) or "XDG_DATA_HOME" in os.environ
    
    def test_expand_user_path(self):
        """Test user path expansion."""
        username = get_current_username()
        
        # Test ${USER} expansion
        expanded = expand_user_path("/home/${USER}/data")
        assert username in expanded
        assert "${USER}" not in expanded
        
        # Test {username} expansion
        expanded = expand_user_path("/Users/{username}/Documents")
        assert username in expanded
        assert "{username}" not in expanded
        
        # Test $USER expansion
        expanded = expand_user_path("/home/$USER/config")
        assert username in expanded
        assert "$USER" not in expanded
        
        # Test ~ expansion
        expanded = expand_user_path("~/config")
        assert str(Path.home()) in expanded
        assert "~" not in expanded
        
        # Test no expansion needed
        expanded = expand_user_path("/absolute/path")
        assert expanded == "/absolute/path"
    
    def test_get_system_info(self):
        """Test getting system information."""
        system_info = get_system_info()
        
        assert isinstance(system_info, dict)
        
        # Check required fields
        required_fields = [
            'username', 'platform', 'platform_version', 
            'python_version', 'home_dir', 'config_dir', 'data_dir'
        ]
        
        for field in required_fields:
            assert field in system_info
            assert system_info[field] is not None
            assert len(str(system_info[field])) > 0
        
        # Validate specific fields
        assert system_info['username'] == get_current_username()
        assert system_info['platform'] == platform.system()
        assert system_info['home_dir'] == str(get_user_home_dir())
        assert system_info['config_dir'] == str(get_user_config_dir())
        assert system_info['data_dir'] == str(get_user_data_dir())
    
    def test_multiple_placeholder_expansion(self):
        """Test expanding multiple placeholders in the same path."""
        username = get_current_username()
        
        path_with_multiple = "/home/${USER}/projects/{username}/config/$USER"
        expanded = expand_user_path(path_with_multiple)
        
        # All placeholders should be replaced
        assert "${USER}" not in expanded
        assert "{username}" not in expanded
        assert "$USER" not in expanded
        
        # Username should appear multiple times
        assert expanded.count(username) == 3
    
    def test_empty_and_none_paths(self):
        """Test handling of edge cases."""
        # Empty string
        assert expand_user_path("") == ""
        
        # Path with no placeholders
        test_path = "/static/path/without/placeholders"
        assert expand_user_path(test_path) == test_path