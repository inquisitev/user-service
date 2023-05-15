from flask import Flask, request
from datetime import date, timedelta
from dataclasses import dataclass
from typing import List


class Cryptographer:
    def __init__(self, secret_key):
        self.secret_key = secret_key

    def encrypt(self, plain_text: str) -> str:
        # TODO: Actually encrypt the string
        return plain_text.swapcase()




@dataclass
class User:
    first_name: str
    last_name: str
    email: str
    encrypted_pass: str

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
        return Token(f"{user.email}_123456789", date.today() + timedelta(days=180))


class UserPerstance:
    # TODO: Actually store things in a database
    # TODO: Encrypt data before it is put into the database and decrypt it after

    def __init__(self):
        self.user_map = {}

    def user_is_known(self, email):
        return email in self.user_map

    def get_user(self, email) -> User:
        if self.user_is_known(email):
            user_struct = self.user_map[email]
            user = user_struct["user"]
            return user

        return None

    def get_tokens(self, email) -> List[Token]:
        if self.user_is_known(email):
            user_struct = self.user_map[email]
            tokens = user_struct["tokens"]
            return tokens

        return []

    def add_token_to_user(self, email, token) -> bool:
        user = self.get_user(email)
        if user is not None:
            self.user_map[email]["tokens"].append(token)
            return True

    def add_user(self, user: User) -> bool:
        if not self.user_is_known(user.email):
            self.user_map[user.email] = {"user": user, "tokens": []}

            return True
        return False


class UserService:
    def __init__(self, crypto, token_factory, persistance):
        self.crypto = crypto
        self.token_factory = token_factory
        self.persistance = persistance

    def create_user(self, first_name, last_name, email, password) -> User:
        encrypted_pass = crypto.encrypt(password)
        user = User(first_name, last_name, email, encrypted_pass)
        if self.persistance.add_user(user):
            return user
        else:
            return None

    def get_user(self, email):
        return self.persistance.get_user(email)

    def user_does_exist(self, email) -> bool:
        return self.persistance.get_user(email) is not None

    def authenticate_user(self, email, password=None, token=None) -> Token:
        user = self.persistance.get_user(email)
        if user is not None:
            encrypted_pass = crypto.encrypt(password)
            if user.encrypted_pass == encrypted_pass:
                new_token = self.get_new_token(user)
                return new_token

        return None

    def get_new_token(self, user) -> Token:
        token = self.token_factory.generate_token(user)
        self.persistance.add_token_to_user(user.email, token)
        return token

    def verify_token(self, email, token) -> bool:
        tokens = self.persistance.get_tokens(email)
        return any([token == ctoken.token for ctoken in tokens])


app = Flask(__name__)

persister = UserPerstance()
crypto = Cryptographer("SECRET_TUNNEL")
authenticator = AuthenticationTokenHandler()
user_service = UserService(crypto, authenticator, persister)


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
