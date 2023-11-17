#!/usr/bin/env python3
"""ALX SE Encryption module"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt module"""
    password = password.encode('utf-8')
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Validate that the provided password matched the hashed password"""
    password = password.encode('utf-8')
    return bcrypt.checkpw(password, hashed_password)
