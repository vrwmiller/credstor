"""
User and system utilities for CredStor.

This module provides utilities for getting user information,
system paths, and environment details.
"""

import os
import pwd
import platform
from pathlib import Path
from typing import Optional


def get_current_username() -> str:
    """
    Get the current system username.
    
    Returns:
        Current username as string
    """
    try:
        # Try environment variable first
        username = os.getenv('USER') or os.getenv('USERNAME')
        if username:
            return username
        
        # Fall back to pwd module on Unix-like systems
        if hasattr(pwd, 'getpwuid'):
            return pwd.getpwuid(os.getuid()).pw_name
        
        # Last resort - use 'user' as default
        return 'user'
    
    except Exception:
        return 'user'


def get_user_home_dir() -> Path:
    """
    Get the current user's home directory.
    
    Returns:
        Path to user's home directory
    """
    return Path.home()


def get_user_config_dir() -> Path:
    """
    Get the user-specific configuration directory for CredStor.
    
    Returns:
        Path to user config directory
    """
    home = get_user_home_dir()
    
    # Use platform-appropriate config directory
    if platform.system() == "Darwin":  # macOS
        return home / "Library" / "Application Support" / "CredStor"
    elif platform.system() == "Windows":
        appdata = os.getenv('APPDATA')
        if appdata:
            return Path(appdata) / "CredStor"
        return home / "AppData" / "Roaming" / "CredStor"
    else:  # Linux and other Unix-like
        xdg_config = os.getenv('XDG_CONFIG_HOME')
        if xdg_config:
            return Path(xdg_config) / "credstor"
        return home / ".config" / "credstor"


def get_user_data_dir() -> Path:
    """
    Get the user-specific data directory for CredStor.
    
    Returns:
        Path to user data directory
    """
    home = get_user_home_dir()
    
    # Use platform-appropriate data directory
    if platform.system() == "Darwin":  # macOS
        return home / "Library" / "Application Support" / "CredStor" / "data"
    elif platform.system() == "Windows":
        appdata = os.getenv('LOCALAPPDATA')
        if appdata:
            return Path(appdata) / "CredStor" / "data"
        return home / "AppData" / "Local" / "CredStor" / "data"
    else:  # Linux and other Unix-like
        xdg_data = os.getenv('XDG_DATA_HOME')
        if xdg_data:
            return Path(xdg_data) / "credstor"
        return home / ".local" / "share" / "credstor"


def get_project_root() -> Optional[Path]:
    """
    Get the CredStor project root directory.
    
    Searches upward from current file location for project markers.
    
    Returns:
        Path to project root or None if not found
    """
    current = Path(__file__).parent
    
    # Look for project markers
    markers = ['requirements.txt', 'setup.py', 'pyproject.toml', '.git']
    
    while current != current.parent:  # Stop at filesystem root
        if any((current / marker).exists() for marker in markers):
            return current
        current = current.parent
    
    return None


def expand_user_path(path_str: str) -> str:
    """
    Expand user path with actual username.
    
    Replaces placeholder patterns like ${USER} or {username} with actual username.
    
    Args:
        path_str: Path string that may contain user placeholders
        
    Returns:
        Expanded path string
    """
    username = get_current_username()
    
    # Replace common placeholder patterns
    expanded = path_str.replace('${USER}', username)
    expanded = expanded.replace('{username}', username)
    expanded = expanded.replace('$USER', username)
    
    # Expand ~ to home directory
    expanded = os.path.expanduser(expanded)
    
    return expanded


def get_system_info() -> dict:
    """
    Get system information for debugging and logging.
    
    Returns:
        Dictionary with system information
    """
    return {
        'username': get_current_username(),
        'platform': platform.system(),
        'platform_version': platform.version(),
        'python_version': platform.python_version(),
        'home_dir': str(get_user_home_dir()),
        'config_dir': str(get_user_config_dir()),
        'data_dir': str(get_user_data_dir()),
    }