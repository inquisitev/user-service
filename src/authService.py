from flask import Flask, request
from datetime import date, timedelta
from dataclasses import dataclass
from typing import List, Tuple
import hashlib
import hmac
import os
import secrets
import string

class Cryptographer:
    def __init__(self, secret_key):
        self.secret_key = secret_key

    def secure_pw(self, plain_text: str) -> Tuple[bytes, bytes]:
        salt = os.urandom(16)
        pw_hash = hashlib.pbkdf2_hmac('sha256', plain_text.encode(), salt, 100000)
        return salt, pw_hash
    
    def check_pw(self, plain_text, hashed_pw, salt):
        return hmac.compare_digest(
            hashed_pw,
            hashlib.pbkdf2_hmac('sha256', plain_text.encode(), salt, 100000)
        )
        
def generate_api_key(length=32):
    alphabet = string.ascii_letters + string.digits
    api_key = ''.join(secrets.choice(alphabet) for _ in range(length))
    return api_key



@dataclass
class User:
    first_name: str
    last_name: str
    email: str
    encrypted_pass: bytes
    salt: bytes

    def to_json(self):
        return {
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
        }


@dataclass
class Token:
    token: str
    expires_on: date

    def to_json(self):
        return {"token": self.token, "expires_on": self.expires_on}


class AuthenticationTokenHandler:
    def generate_token(self, user: User) -> Token:
        # TODO: Actually make a token
        return Token(generate_api_key(), date.today() + timedelta(days=180))


class UserPerstance:
    # TODO: Actually store things in a database
    # TODO: secure_pw data before it is put into the database and decrypt it after

    def __init__(self):
        self.user_map = {}

    def user_is_known(self, email: str) -> bool:
        """Check if the user is known in this persistent storage apparatus

        Args:
            email (str): the email of the user

        Returns:
            bool: true if the user is known
        """
        return email in self.user_map

    def get_user(self, email: str) -> User:
        """get the user with the associated email, if possible

        Args:
            email (str): the email of the user

        Returns:
            User: the user with the email address, if theyre known.
        """
        if self.user_is_known(email):
            user_struct = self.user_map[email]
            user = user_struct["user"]
            return user

        return None

    def get_tokens(self, email: str) -> List[Token]:
        """get all of the tokens for the user with the email address

        Args:
            email (str): the email of the user

        Returns:
            List[Token]: the tokens registered to the user
        """
        if self.user_is_known(email):
            user_struct = self.user_map[email]
            tokens = user_struct["tokens"]
            return tokens

        return []

    def add_token_to_user(self, email: str, token: str) -> bool:
        """Save a token to the user with email

        Args:
            email (str): the email of the user
            token (str): the token to save

        Returns:
            bool: true if successfully saved
        """
        user = self.get_user(email)
        if user is not None:
            self.user_map[email]["tokens"].append(token)
            return True

    def add_user(self, user: User) -> bool:
        """add a user to the persistent storage apparatus

        Args:
            user (User): the user to save

        Returns:
            bool: true if successfully saved
        """
        if not self.user_is_known(user.email):
            self.user_map[user.email] = {"user": user, "tokens": []}
            return True
        return False


class UserService:
    def __init__(self, crypto, token_factory, persistance):
        self.crypto = crypto
        self.token_factory = token_factory
        self.persistance = persistance

    def create_user(
        self, first_name: str, last_name: str, email: str, password: str
    ) -> User:
        """Create a user

        Args:
            first_name (str): The first name of the user
            last_name (str): The last name of the user
            email (str): The email of the user
            password (str): The password of the user

        Returns:
            User: The details of the user that has been added, excluding password.
            if the user has not been added for some reason, return None
        """
        salt, encrypted_pass = crypto.secure_pw(password)
        user = User(first_name, last_name, email, encrypted_pass, salt)
        if self.persistance.add_user(user):
            return user
        else:
            return None

    def get_user(self, email: str) -> User:
        """Get the user with the email from persistent storage

        Args:
            email (str): the email of the user

        Returns:
            User: the User with the email address, None if 
            retrieved from persistent storage as None
        """
        return self.persistance.get_user(email)

    def user_does_exist(self, email: str) -> bool:
        """Check if the user with email exists

        Args:
            email (str): the email of the user

        Returns:
            bool: true if the user exists
        """
        return self.persistance.get_user(email) is not None

    def authenticate_user(self, email: str, password: str) -> Token:
        """Generate a new token for a user provided that
        they have supplied correct credentials

        Args:
            email (str): the email of the user
            password (str): the plaintext password that will
                be verified against the stored encrypted password

        Returns:
            Token: The new authentication token attached to the user
                with the email
        """
        user = self.persistance.get_user(email)
        if user is not None:
            pw_is_correct = crypto.check_pw(password, user.encrypted_pass, user.salt)
            if pw_is_correct:
                new_token = self.get_new_token(user)
                return new_token

        return None

    def get_new_token(self, user: User) -> Token:
        """Get a new token for the user

        Args:
            user (User): the user to create a new token for.

        Returns:
            Token: the new token used for authentication. 
        """
        token = self.token_factory.generate_token(user)
        self.persistance.add_token_to_user(user.email, token)
        return token

    def verify_token(self, email: str, token: Token) -> bool:
        """Verify an authenitcation token with what is known already

        Args:
            email (str): the email of the user
            token (str): the token to attempt verification with

        Returns:
            bool: true if verification successful
        """
        tokens = self.persistance.get_tokens(email)
        return any([token == ctoken.token for ctoken in tokens])


app = Flask(__name__)

persister = UserPerstance()
crypto = Cryptographer("SECRET_TUNNEL")
authenticator = AuthenticationTokenHandler()
user_service = UserService(crypto, authenticator, persister)


@app.route("/", methods=["GET"])
def index():
    return {}, 200

@app.route("/users/new", methods=["POST"])
def create_user():
    request_data = request.json

    user = user_service.create_user(**request_data)
    if user is not None:
        token = user_service.get_new_token(user)
        response_payload = token.to_json()
        return response_payload, 200

    else:
        return {"message": "An account with that email already exists."}, 409


@app.route("/users/verify", methods=["POST"])
def verify_user():
    request_data = request.json
    verified = user_service.verify_token(**request_data)
    response_payload = {"verified": verified}

    return response_payload, 200


@app.route("/users/login", methods=["POST"])
def authenticate_user():
    request_data = request.json
    if not user_service.user_does_exist(request_data["email"]):
        message = {"message": "There is no account with that email."}
        return message, 409
    else:
        new_token = user_service.authenticate_user(**request_data)

        if new_token is not None:
            return new_token.to_json(), 200
        else:
            message = {"message": "Incorrect credentials."}
            return message, 409


@app.route("/users/user_info", methods=["POST"])
def lookup_user():
    request_data = request.json
    email = request_data["email"]
    if not user_service.user_does_exist(email):
        message = {"message": "There is no account with that email."}
        return message, 409
    else:
        verified = user_service.verify_token(**request_data)

        if verified:
            user = user_service.get_user(email)
            return user.to_json(), 200
        else:
            message = {"message": "Incorrect credentials."}
            return message, 409
