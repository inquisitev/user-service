from flask import Flask, request
from datetime import date, timedelta
from dataclasses import dataclass
from typing import List

class Persister:
    pass

    
class Cryptographer:
    
    def __init__(self, secret_key):
        self.secret_key = secret_key
    
    def encrypt(self, plain_text) -> str:
        return plain_text
    
    def compare(self, plain_text, encrypted_text) -> str:
        pass

@dataclass
class User:
    first_name: str
    last_name: str
    email: str
    encrypted_pass: str
    
    
    def to_json(self):
        return {
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email
        }

@dataclass
class Token:
    token: str
    expires_on: date
    
    def to_json(self):
        return {
            'token': self.token,
            'expires_on': self.expires_on
        }
        
        
class AuthenticationTokenHandler:
    def generate_token(self, user: User) -> Token:
        return Token(f"{user.email}_123456789", date.today() + timedelta(days=180))
    
        
class UserPerstance:
    
    def get_user(self, email) -> User:
        pass

    def get_tokens(self, email, password) -> List[Token]:
        pass
    
    def add_user(self, user:User):
        pass

class UserService:
    def __init__(self, crypto, token_factory, persistance):
        self.crypto = crypto
        self.token_factory = token_factory
        self.persistance = persistance
        
    def create_user(self, first_name, last_name, email, password) -> User:
        encrypted_pass = crypto.encrypt(password)
        user = User(first_name, last_name, email, encrypted_pass)
        return user
        
    
    def get_new_token(self, user) -> Token:
        return self.token_factory.generate_token(user)
    
    def clear_tokens(self, email, password) -> bool:
        pass

    def verify_token(self, email, token) -> bool:
        pass

app = Flask(__name__)

persister = Persister()
crypto = Cryptographer('SECRET_TUNNEL')
authenticator = AuthenticationTokenHandler()
user_service = UserService(crypto, authenticator, persister)

@app.route('/users/new', methods=['POST'])
def create_user():
    
    request_data = request.json
    
    user = user_service.create_user(**request_data)
    token = user_service.get_new_token(user)
    
    response_payload = token.to_json()
    return response_payload, 200


@app.route('/users/verify', methods=['POST'])
def verify_user():
    
    
    response_payload = {}
    
    return response_payload, 200