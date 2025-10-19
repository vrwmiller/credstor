"""
Security and encryption utilities for CredStor.

This module provides encryption/decryption functions, key derivation,
and other security-related utilities using industry-standard algorithms.
"""

import os
import base64
import secrets
import logging
from typing import Union, Tuple, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

try:
    from ..utils.config import get_config
except ImportError:
    # Fallback for direct execution
    from utils.config import get_config

logger = logging.getLogger(__name__)

# Constants
AES_KEY_SIZE = 32  # 256 bits
AES_NONCE_SIZE = 12  # 96 bits for GCM
SALT_SIZE = 32  # 256 bits
TAG_SIZE = 16  # 128 bits for GCM


class EncryptionError(Exception):
    """Base exception for encryption operations."""
    pass


class DecryptionError(Exception):
    """Base exception for decryption operations."""
    pass


class KeyDerivationError(Exception):
    """Base exception for key derivation operations."""
    pass


def secure_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length: Number of bytes to generate
        
    Returns:
        Random bytes
    """
    return secrets.token_bytes(length)


def generate_salt() -> bytes:
    """
    Generate a random salt for key derivation.
    
    Returns:
        Random salt bytes
    """
    return secure_random_bytes(SALT_SIZE)


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derive encryption key from password using PBKDF2.
    
    Args:
        password: Master password
        salt: Random salt bytes
        
    Returns:
        Derived key bytes
        
    Raises:
        KeyDerivationError: If key derivation fails
    """
    try:
        config = get_config()
        
        # Convert password to bytes
        password_bytes = password.encode('utf-8')
        
        # Create PBKDF2 key derivation function
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=config.security.key_iterations,
        )
        
        # Derive key
        key = kdf.derive(password_bytes)
        
        logger.debug("Key derived from password using PBKDF2")
        return key
        
    except Exception as e:
        logger.error(f"Key derivation failed: {e}")
        raise KeyDerivationError(f"Failed to derive key from password: {e}")


def hash_password(password: str) -> str:
    """
    Hash password using Argon2.
    
    Args:
        password: Password to hash
        
    Returns:
        Hashed password string
    """
    try:
        ph = PasswordHasher()
        hashed = ph.hash(password)
        
        logger.debug("Password hashed using Argon2")
        return hashed
        
    except Exception as e:
        logger.error(f"Password hashing failed: {e}")
        raise


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify password against Argon2 hash.
    
    Args:
        password: Plain text password
        hashed: Hashed password
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        ph = PasswordHasher()
        ph.verify(hashed, password)
        
        logger.debug("Password verification successful")
        return True
        
    except VerifyMismatchError:
        logger.debug("Password verification failed")
        return False
        
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


def encrypt_data(data: Union[str, bytes], key: bytes) -> bytes:
    """
    Encrypt data using AES-256-GCM.
    
    Args:
        data: Data to encrypt (string or bytes)
        key: Encryption key (32 bytes)
        
    Returns:
        Encrypted data with nonce and tag prepended
        
    Raises:
        EncryptionError: If encryption fails
    """
    try:
        # Convert string to bytes if necessary
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Generate random nonce
        nonce = secure_random_bytes(AES_NONCE_SIZE)
        
        # Create cipher
        aesgcm = AESGCM(key)
        
        # Encrypt data
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # Return nonce + ciphertext (ciphertext includes auth tag)
        encrypted = nonce + ciphertext
        
        logger.debug(f"Data encrypted, size: {len(data)} -> {len(encrypted)} bytes")
        return encrypted
        
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise EncryptionError(f"Failed to encrypt data: {e}")


def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypt data using AES-256-GCM.
    
    Args:
        encrypted_data: Encrypted data with nonce and tag
        key: Decryption key (32 bytes)
        
    Returns:
        Decrypted data bytes
        
    Raises:
        DecryptionError: If decryption fails
    """
    try:
        # Extract nonce and ciphertext
        if len(encrypted_data) < AES_NONCE_SIZE:
            raise DecryptionError("Invalid encrypted data: too short")
        
        nonce = encrypted_data[:AES_NONCE_SIZE]
        ciphertext = encrypted_data[AES_NONCE_SIZE:]
        
        # Create cipher
        aesgcm = AESGCM(key)
        
        # Decrypt data
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        logger.debug(f"Data decrypted, size: {len(encrypted_data)} -> {len(plaintext)} bytes")
        return plaintext
        
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise DecryptionError(f"Failed to decrypt data: {e}")


def encrypt_string(text: str, key: bytes) -> str:
    """
    Encrypt string and return base64-encoded result.
    
    Args:
        text: Text to encrypt
        key: Encryption key
        
    Returns:
        Base64-encoded encrypted data
    """
    encrypted_bytes = encrypt_data(text, key)
    return base64.b64encode(encrypted_bytes).decode('ascii')


def decrypt_string(encrypted_text: str, key: bytes) -> str:
    """
    Decrypt base64-encoded string.
    
    Args:
        encrypted_text: Base64-encoded encrypted data
        key: Decryption key
        
    Returns:
        Decrypted text
    """
    encrypted_bytes = base64.b64decode(encrypted_text.encode('ascii'))
    decrypted_bytes = decrypt_data(encrypted_bytes, key)
    return decrypted_bytes.decode('utf-8')


def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    """
    Generate Ed25519 public/private key pair.
    
    Returns:
        Tuple of (private_key_bytes, public_key_bytes)
    """
    try:
        # Generate private key
        private_key = ed25519.Ed25519PrivateKey.generate()
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize keys
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        logger.debug("Ed25519 key pair generated")
        return private_bytes, public_bytes
        
    except Exception as e:
        logger.error(f"Key pair generation failed: {e}")
        raise


def sign_data(data: bytes, private_key_bytes: bytes) -> bytes:
    """
    Sign data using Ed25519 private key.
    
    Args:
        data: Data to sign
        private_key_bytes: Ed25519 private key bytes
        
    Returns:
        Signature bytes
    """
    try:
        # Load private key
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        
        # Sign data
        signature = private_key.sign(data)
        
        logger.debug(f"Data signed, signature size: {len(signature)} bytes")
        return signature
        
    except Exception as e:
        logger.error(f"Data signing failed: {e}")
        raise


def verify_signature(data: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
    """
    Verify signature using Ed25519 public key.
    
    Args:
        data: Original data
        signature: Signature to verify
        public_key_bytes: Ed25519 public key bytes
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Load public key
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        
        # Verify signature
        public_key.verify(signature, data)
        
        logger.debug("Signature verification successful")
        return True
        
    except InvalidSignature:
        logger.debug("Signature verification failed")
        return False
        
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        return False


def secure_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """
    Constant-time comparison to prevent timing attacks.
    
    Args:
        a: First value
        b: Second value
        
    Returns:
        True if values are equal, False otherwise
    """
    # Convert to bytes if necessary
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    
    return secrets.compare_digest(a, b)


def generate_master_key(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Generate master encryption key from password.
    
    Args:
        password: Master password
        salt: Optional salt (generates new one if not provided)
        
    Returns:
        Tuple of (key, salt)
    """
    if salt is None:
        salt = generate_salt()
    
    key = derive_key_from_password(password, salt)
    return key, salt


def clear_memory(data: Union[str, bytes, bytearray]) -> None:
    """
    Attempt to clear sensitive data from memory.
    
    Note: This is a best-effort approach. Python's memory management
    makes it difficult to guarantee that sensitive data is completely
    removed from memory.
    
    Args:
        data: Data to clear from memory
    """
    try:
        if isinstance(data, str):
            # Cannot clear immutable strings in Python
            logger.debug("Cannot clear immutable string from memory")
            return
        
        if isinstance(data, (bytes, bytearray)):
            # Overwrite mutable data
            if hasattr(data, '__setitem__'):
                for i in range(len(data)):
                    data[i] = 0
                logger.debug("Memory cleared for mutable data")
            else:
                logger.debug("Cannot clear immutable bytes from memory")
        
    except Exception as e:
        logger.debug(f"Memory clearing failed: {e}")


def get_encryption_key_from_config() -> bytes:
    """
    Get encryption key from configuration.
    
    Returns:
        Encryption key bytes
        
    Raises:
        KeyDerivationError: If key cannot be obtained
    """
    try:
        config = get_config()
        
        # Get base64-encoded key from config
        key_b64 = config.database.encryption_key
        if not key_b64:
            raise KeyDerivationError("No encryption key found in configuration")
        
        # Decode base64 key
        key = base64.b64decode(key_b64)
        
        # Validate key length
        if len(key) != AES_KEY_SIZE:
            raise KeyDerivationError(f"Invalid key length: expected {AES_KEY_SIZE}, got {len(key)}")
        
        logger.debug("Encryption key loaded from configuration")
        return key
        
    except Exception as e:
        logger.error(f"Failed to get encryption key: {e}")
        raise KeyDerivationError(f"Failed to get encryption key: {e}")


class SecureString:
    """
    A wrapper class for handling sensitive strings with automatic cleanup.
    
    This class attempts to provide some protection for sensitive data
    by clearing it from memory when the object is destroyed.
    """
    
    def __init__(self, value: str):
        """Initialize with sensitive string value."""
        self._value = bytearray(value.encode('utf-8'))
    
    def get(self) -> str:
        """Get the string value."""
        return bytes(self._value).decode('utf-8')
    
    def clear(self) -> None:
        """Clear the sensitive data from memory."""
        clear_memory(self._value)
        self._value = bytearray()
    
    def __del__(self):
        """Clear data when object is destroyed."""
        self.clear()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - clear data."""
        self.clear()