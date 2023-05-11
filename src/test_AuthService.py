import json
import pytest
from authService import app
from datetime import date, timedelta

    

# test that i can add a user and verify with the auth token i am given
def test_adding_a_user():
    client = app.test_client()
        
    response = client.post('/users/new', json={
        'first_name': 'duckey',
        'last_name': 'beaver',
        'email': 'duckey@olivesToys.com',
        'password': 'mollyAndOliveAreBuddies'
    })
    
    required_keys = ['expires_on', 'token']
    assert all([x in response.json for x in required_keys])
    token = response.json['token']
    assert response.status_code == 200
    
    response = client.post('/users/verify', json={
        'token': token,
        'email': 'duckey@olivesToys.com'
    })
    
    assert response.status_code == 200
    

# test that when adding a new user, if the email is already registered, then do not provide auth token
def test_emails_must_be_unique():
    client = app.test_client()
        
    response = client.post('/users/new', json={
        'first_name': 'duckey',
        'last_name': 'beaver',
        'email': 'duckey@olivesToys.com'
    })
    
    required_keys = ['expires_on', 'token']
    assert all([x in response.json for x in required_keys])
    token = response.json[token]
    assert response.status_code == 200
    
    response = client.post('/users/new', json={
        'first_name': 'Daddy',
        'last_name': 'Dolphin',
        'email': 'duckey@olivesToys.com',
        'password': 'mollyAndOliveAreBuddies'
    })
    
    assert response.status_code == 409
    required_keys = ['expires_on', 'token']
    assert all([x not in response.json for x in required_keys])
    
    

# test authenticating in as a user

# test validating a token for a user

# test getting the details for a user



 