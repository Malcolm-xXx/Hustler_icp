import uuid
import time
import hashlib
import hmac
import secrets
from typing import Optional, Tuple
from kybra import init, update, query

# Initialize the Kybra canister
init("huster_backend")

class User:
    def __init__(self, principal: str, username: str, email: str, password_hash: str):
        self.principal = principal
        self.username = username
        self.email = email
        self.logged_in = False
        self.reset_token: Optional[str] = None
        self.password_hash = password_hash

class UserService:
    def __init__(self):
        self.users = []

    @update
    def register_user(self, username: str, email: str, password: str) -> bool:
        """Register a new user."""
        if any(user.email == email for user in self.users):
            print(f"User already registered with email: {email}")
            return False

        # Hash the password using bcrypt
        password_hash = self._hash_password(password)

        new_user = User(str(uuid.uuid4()), username, email, password_hash)
        new_user.logged_in = True
        self.users.append(new_user)
        print(f"User registered: {username}")
        return True

    def _hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        salt = secrets.token_bytes(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return f"pbkdf2_sha256${salt.hex()}${password_hash.hex()}"

    @update
    def login_user(self, principal: str) -> bool:
        """Login a user."""
        for user in self.users:
            if user.principal == principal:
                user.logged_in = True
                print(f"User logged in: {user.username}")
                return True
        print("User not found, cannot log in.")
        return False

    @update
    def logout_user(self, principal: str) -> bool:
        """Logout a user."""
        for user in self.users:
            if user.principal == principal:
                user.logged_in = False
                print(f"User logged out: {user.username}")
                return True
        print("User not found, cannot log out.")
        return False

    @query
    def is_user_logged_in(self, principal: str) -> bool:
        """Check if a user is logged in."""
        for user in self.users:
            if user.principal == principal:
                return user.logged_in
        print("User not found.")
        return False

    @query
    def get_user_info(self, principal: str) -> Optional[Tuple[str, str]]:
        """Get a user's information."""
        for user in self.users:
            if user.principal == principal:
                return user.username, user.email
        print("User not found.")
        return None

    @update
    def reset_password(self, email: str) -> bool:
        """Request a password reset."""
        for user in self.users:
            if user.email == email:
                token = self._generate_reset_token()
                user.reset_token = token
                print(f"Password reset requested for: {email} with token: {token}")
                # TODO: Call an email API to send the reset token to the user's email.
                return True
        print(f"User with email {email} not found.")
        return False

    def _generate_reset_token(self) -> str:
        """Generate a cryptographically secure token for password reset."""
        return secrets.token_urlsafe(16)

    @update
    def verify_reset_token_and_reset_password(self, email: str, token: str, new_password: str) -> bool:
        """Verify the token and reset the password."""
        for user in self.users:
            if user.email == email and user.reset_token == token:
                # Hash the new password using bcrypt
                new_password_hash = self._hash_password(new_password)
                user.password