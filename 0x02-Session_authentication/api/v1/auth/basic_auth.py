#!/usr/bin/env python3
"""Basic auth module"""
from api.v1.auth.auth import Auth
import base64
from typing import TypeVar
from models.user import User
from models.base import DATA


class BasicAuth(Auth):
    """Basic auth class"""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Extract base64 authorization header"""
        if authorization_header is None:
            return None
        if type(authorization_header) is not str:
            return None
        if not authorization_header.startswith('Basic '):
            return None
        auth_val = authorization_header.split()[-1]
        return auth_val

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Decode base64 authorization header"""
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) is not str:
            return None
        try:
            res = base64.b64decode(base64_authorization_header.encode('utf-8'))
            decoded_string = res.decode('utf-8')
            return decoded_string
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """Extract user credentials from decoded auth header"""
        if decoded_base64_authorization_header is None:
            return None, None
        if type(decoded_base64_authorization_header) is not str:
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        res = decoded_base64_authorization_header.split(':', 1)
        return res[0], res[-1]

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """Get user object from supplied credentials"""
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None
        if 'User' not in DATA:
            return None
        users = User.search({'email': user_email})
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Retrieves user instance for a request"""
        header = self.authorization_header(request)
        if not header:
            return None
        extracted_header = self.extract_base64_authorization_header(header)
        if not extracted_header:
            return None
        decoded = self.decode_base64_authorization_header(extracted_header)
        if not decoded:
            return None
        user_cred = self.extract_user_credentials(decoded)
        if not user_cred:
            return None
        user = self.user_object_from_credentials(user_cred[0], user_cred[1])
        return user
