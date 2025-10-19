"""
Tests for cryptographic functions.
"""

import pytest
from src.security.crypto import (
    encrypt_data, decrypt_data, encrypt_string, decrypt_string,
    generate_salt, derive_key_from_password, hash_password, verify_password,
    secure_compare, EncryptionError, DecryptionError
)


def test_encrypt_decrypt_data():
    """Test data encryption and decryption."""
    key = b"0" * 32  # 32-byte key for AES-256
    data = b"Hello, World!"
    
    encrypted = encrypt_data(data, key)
    assert encrypted != data
    assert len(encrypted) > len(data)  # Encrypted data is longer due to nonce and tag
    
    decrypted = decrypt_data(encrypted, key)
    assert decrypted == data


def test_encrypt_decrypt_string():
    """Test string encryption and decryption."""
    key = b"1" * 32  # 32-byte key for AES-256
    text = "Hello, World!"
    
    encrypted = encrypt_string(text, key)
    assert encrypted != text
    assert isinstance(encrypted, str)  # Base64 encoded
    
    decrypted = decrypt_string(encrypted, key)
    assert decrypted == text


def test_password_hashing():
    """Test password hashing and verification."""
    password = "test_password_123"
    
    hashed = hash_password(password)
    assert hashed != password
    assert len(hashed) > 50  # Argon2 hashes are long
    
    # Verify correct password
    assert verify_password(password, hashed) is True
    
    # Verify incorrect password
    assert verify_password("wrong_password", hashed) is False


def test_key_derivation():
    """Test key derivation from password."""
    password = "test_password"
    salt = generate_salt()
    
    key1 = derive_key_from_password(password, salt)
    key2 = derive_key_from_password(password, salt)
    
    # Same password and salt should generate same key
    assert key1 == key2
    assert len(key1) == 32  # 256 bits
    
    # Different salt should generate different key
    different_salt = generate_salt()
    key3 = derive_key_from_password(password, different_salt)
    assert key1 != key3


def test_secure_compare():
    """Test constant-time comparison."""
    assert secure_compare("hello", "hello") is True
    assert secure_compare("hello", "world") is False
    assert secure_compare(b"hello", b"hello") is True
    assert secure_compare(b"hello", b"world") is False
    
    # Mixed string and bytes
    assert secure_compare("hello", b"hello") is True


def test_salt_generation():
    """Test salt generation."""
    salt1 = generate_salt()
    salt2 = generate_salt()
    
    assert len(salt1) == 32  # 256 bits
    assert len(salt2) == 32
    assert salt1 != salt2  # Should be different


def test_encryption_error_handling():
    """Test encryption error handling."""
    # Invalid key length
    with pytest.raises(Exception):  # Should raise an exception
        encrypt_data(b"test", b"short_key")


def test_decryption_error_handling():
    """Test decryption error handling."""
    key = b"0" * 32
    
    # Invalid encrypted data (too short)
    with pytest.raises(DecryptionError):
        decrypt_data(b"short", key)
    
    # Corrupted data
    valid_encrypted = encrypt_data(b"test", key)
    corrupted = valid_encrypted[:-1] + b"X"  # Change last byte
    
    with pytest.raises(DecryptionError):
        decrypt_data(corrupted, key)