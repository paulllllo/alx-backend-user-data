#!/usr/bin/env python3
"""Authentication module"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid
from typing import Union


def _hash_password(password: str) -> bytes:
    """Hash a password using bcrypt module"""
    password = password.encode('utf-8')
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed


def _generate_uuid() -> str:
    """Generate an ID using the uuid module"""
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initialize the class"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user in the DB"""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError("User {} already exists".format(email))
        except NoResultFound:
            hashed_password = _hash_password(password).decode('utf-8')
            new_user = self._db.add_user(email, hashed_password)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """Validates a user's login credentials"""
        try:
            user = self._db.find_user_by(email=email)
            hashed_password = user.hashed_password.encode('utf-8')
            password = password.encode('utf-8')
            return bcrypt.checkpw(password, hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """creates a new user session"""
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Gets user from session ID"""
        if not session_id:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id) -> None:
        """Destroy the user session"""
        try:
            self._db.update_user(user_id, session_id=None)
        except Exception:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """Update the user reset_password token"""
        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """updates the user password given a correct reset_token"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password).decode('utf-8')
            self._db.update_user(
                    user.id, hashed_password=hashed_password, reset_token=None)
        except NoResultFound:
            raise ValueError
