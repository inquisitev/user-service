import pytest
from src.authService import app, persister


# must clear the user map so that adding the same test user multiple times doesnt break 
# the test suite
@pytest.fixture(autouse=True)
def reset_test_env():
    persister.user_map.clear()


# test that i can add a user and verify with the auth token i am given
def test_adding_a_user():
    client = app.test_client()

    response = client.post(
        "/users/new",
        json={
            "first_name": "duckey",
            "last_name": "beaver",
            "email": "duckey@olivesToys.com",
            "password": "mollyAndOliveAreBuddies",
        },
    )

    required_keys = ["expires_on", "token"]
    assert all([x in response.json for x in required_keys])
    token = response.json["token"]
    assert response.status_code == 200

    response = client.post(
        "/users/verify", json={"token": token, "email": "duckey@olivesToys.com"}
    )

    assert response.status_code == 200
    assert response.json["verified"] is True


# test that a wrong token will not verify
def test_a_incorrect_token_will_not_verify():
    client = app.test_client()

    response = client.post(
        "/users/new",
        json={
            "first_name": "duckey",
            "last_name": "beaver",
            "email": "chickum@olivesToys.com",
            "password": "mollyAndOliveAreBuddies",
        },
    )

    required_keys = ["expires_on", "token"]
    assert all([x in response.json for x in required_keys])
    assert response.status_code == 200

    response = client.post(
        "/users/verify",
        json={"token": "INVALID_TOKEN", "email": "duckey@olivesToys.com"},
    )

    assert response.status_code == 200
    assert response.json["verified"] is False


# test that a wrong token will not verify
def test_a_different_users_token_will_not_verify():
    client = app.test_client()

    response = client.post(
        "/users/new",
        json={
            "first_name": "duckey",
            "last_name": "beaver",
            "email": "chickum@olivesToys.com",
            "password": "mollyAndOliveAreBuddies",
        },
    )

    token = response.json["token"]

    response = client.post(
        "/users/new",
        json={
            "first_name": "duckey",
            "last_name": "beaver2",
            "email": "beaver@olivesToys.com",
            "password": "mollyAndOliveAreBuddies",
        },
    )

    response = client.post(
        "/users/verify", json={"token": token, "email": "beaver@olivesToys.com"}
    )

    assert response.status_code == 200
    assert response.json["verified"] is False


# test that when adding a new user, if the email is already registered, then do not 
# provide auth token
def test_emails_must_be_unique():
    client = app.test_client()

    response = client.post(
        "/users/new",
        json={
            "first_name": "duckey",
            "last_name": "beaver",
            "email": "chickum@olivesToys.com",
            "password": "mollyAndOliveAreBuddies",
        },
    )

    required_keys = ["expires_on", "token"]
    assert all([x in response.json for x in required_keys])
    assert response.status_code == 200

    response = client.post(
        "/users/new",
        json={
            "first_name": "Daddy",
            "last_name": "Dolphin",
            "email": "chickum@olivesToys.com",
            "password": "mollyAndOliveAreBuddies",
        },
    )

    assert response.status_code == 409
    required_keys = ["expires_on", "token"]
    assert not any([x in response.json for x in required_keys])
    assert "message" in response.json
    assert response.json["message"] == "An account with that email already exists."


# test getting the details for a user


def test_a_user_can_log_in_if_they_haven_an_account():
    client = app.test_client()

    response = client.post(
        "/users/new",
        json={
            "first_name": "duckey",
            "last_name": "beaver",
            "email": "duckey@olivesToys.com",
            "password": "mollyAndOliveAreBuddies",
        },
    )

    response = client.post(
        "/users/login",
        json={"email": "duckey@olivesToys.com", "password": "mollyAndOliveAreBuddies"},
    )

    assert response.status_code == 200
    required_keys = ["expires_on", "token"]
    assert all([x in response.json for x in required_keys])


def test_a_user_can_not_log_in_if_they_dont_have_an_account():
    client = app.test_client()

    response = client.post(
        "/users/login",
        json={"email": "duckey@olivesToys.com", "password": "mollyAndOliveAreBuddies"},
    )

    assert response.status_code == 409
    assert "message" in response.json
    assert response.json["message"] == "There is no account with that email."


def test_a_user_can_not_log_in_if_they_have_the_wrong_password():
    client = app.test_client()

    response = client.post(
        "/users/new",
        json={
            "first_name": "duckey",
            "last_name": "beaver",
            "email": "duckey@olivesToys.com",
            "password": "mollyAndOliveNOTAreBuddies",
        },
    )

    response = client.post(
        "/users/login",
        json={"email": "duckey@olivesToys.com", "password": "mollyAndOliveAreBuddies"},
    )

    assert response.status_code == 409
    assert "message" in response.json
    assert response.json["message"] == "Incorrect credentials."


def test_get_into_of_a_user_that_does_not_exist():
    client = app.test_client()

    response = client.post(
        "/users/user_info",
        json={"email": "duckey@olivesToys.com", "token": "982034576_fgasdfa"},
    )

    assert response.status_code == 409
    assert "message" in response.json
    assert response.json["message"] == "There is no account with that email."


def test_get_info_of_a_user_that_exists():
    client = app.test_client()

    client.post(
        "/users/new",
        json={
            "first_name": "duckey",
            "last_name": "beaver",
            "email": "duckey@olivesToys.com",
            "password": "mollyAndOliveNOTAreBuddies",
        },
    )

    response = client.post(
        "/users/login",
        json={
            "email": "duckey@olivesToys.com",
            "password": "mollyAndOliveNOTAreBuddies",
        },
    )

    token = response.json["token"]

    response = client.post(
        "/users/user_info", json={"email": "duckey@olivesToys.com", "token": token}
    )

    assert response.status_code == 200
    assert response.json == {
        "first_name": "duckey",
        "last_name": "beaver",
        "email": "duckey@olivesToys.com",
    }


def test_get_info_for_user_that_exists_but_authentication_fails():
    client = app.test_client()

    client.post(
        "/users/new",
        json={
            "first_name": "duckey",
            "last_name": "beaver",
            "email": "duckey@olivesToys.com",
            "password": "mollyAndOliveNOTAreBuddies",
        },
    )

    response = client.post(
        "/users/user_info",
        json={"email": "duckey@olivesToys.com", "token": "INCORRECT_TOKEN"},
    )

    assert response.status_code == 409
    assert response.json == {
        "message": "Incorrect credentials.",
    }
