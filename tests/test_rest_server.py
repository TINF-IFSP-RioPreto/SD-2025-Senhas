import pytest

from src.jwtokens import criar_token_jwt
from src.jwtokens.rest_server import app, init_db, SECRET_KEY


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['DATABASE'] = 'temp.db'
    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client


def create_jwt_token(action, role, expires_in: int = 30):
    return criar_token_jwt(sub='user@domain.tld', sign_key=SECRET_KEY, action=action,
                           expires_in=expires_in, extra_data={'role': role})


def test_list_users(client):
    response = client.get('/users')
    assert response.status_code == 200
    assert response.json == []


def test_get_non_existing_user(client):
    response = client.get('/user/example@example.com')
    assert response.status_code == 404
    assert response.json == {'error': 'User not found'}


def test_create_user(client):
    token = create_jwt_token("create", 'admin')
    headers = {'Authorization': token, 'Content-Type': 'application/json'}
    data = {
        "email"    : "example@example.com",
        "name"     : "John Doe",
        "telephone": "123-456-7890"
    }
    response = client.post('/new', headers=headers, json=data)
    assert response.status_code == 200
    assert response.json == {'message': 'User created'}

    response = client.get('/users')
    assert response.status_code == 200
    assert response.json == [
        {'email': 'example@example.com', 'name': 'John Doe', 'telephone': '123-456-7890'}]


def test_create_duplicated_user(client):
    token = create_jwt_token("create", 'admin')
    headers = {'Authorization': token, 'Content-Type': 'application/json'}
    data = {
        "email"    : "example@example.com",
        "name"     : "John Doe",
        "telephone": "123-456-7890"
    }
    response = client.post('/new', headers=headers, json=data)
    assert response.status_code == 200
    assert response.json == {'message': 'User created'}

    response = client.post('/new', headers=headers, json=data)
    assert response.status_code == 400
    assert response.json == {'error': 'User already exists'}


def test_create_user_missing_data(client):
    token = create_jwt_token("create", 'admin')
    headers = {'Authorization': token, 'Content-Type': 'application/json'}
    data = {
        "email"    : "example@example.com",
        "telephone": "123-456-7890"
    }
    response = client.post('/new', headers=headers, json=data)
    assert response.status_code == 400


def test_expired_token(client):
    token = create_jwt_token("create", 'admin', expires_in=-10)
    headers = {'Authorization': token, 'Content-Type': 'application/json'}
    data = {
        "email"    : "example@example.com",
        "name"     : "John Doe",
        "telephone": "123-456-7890"
    }
    response = client.post('/new', headers=headers, json=data)
    assert response.status_code == 403


def test_no_token(client):
    headers = {}
    data = {
        "email"    : "example@example.com",
        "name"     : "John Doe",
        "telephone": "123-456-7890"
    }
    response = client.post('/new', headers=headers, json=data)
    assert response.status_code == 403


def test_invalid_token(client):
    token = 'InvalidToken'
    headers = {'Authorization': token, 'Content-Type': 'application/json'}
    data = {
        "email"    : "example@example.com",
        "name"     : "John Doe",
        "telephone": "123-456-7890"
    }
    response = client.post('/new', headers=headers, json=data)
    assert response.status_code == 403


def test_create_user_no_auth(client):
    token = create_jwt_token("create", 'user')
    headers = {'Authorization': token, 'Content-Type': 'application/json'}
    data = {
        "email"    : "example@example.com",
        "name"     : "John Doe",
        "telephone": "123-456-7890"
    }
    response = client.post('/new', headers=headers, json=data)
    assert response.status_code == 403


def test_update_user(client):
    token = create_jwt_token("create", 'admin')
    headers = {'Authorization': token, 'Content-Type': 'application/json'}
    data = {
        "email"    : "example@example.com",
        "name"     : "John Doe",
        "telephone": "123-456-7890"
    }
    response = client.post('/new', headers=headers, json=data)
    assert response.status_code == 200
    assert response.json == {'message': 'User created'}

    token = create_jwt_token("update", 'admin')
    headers = {'Authorization': token, 'Content-Type': 'application/json'}
    data = {
        "name"     : "Jane Doe",
        "telephone": "987-654-3210"
    }
    response = client.put('/user/example@example.com', headers=headers, json=data)
    assert response.status_code == 200
    assert response.json == {'message': 'User updated'}

    response = client.get('/user/example@example.com')
    assert response.status_code == 200
    assert response.json == {'email'    : 'example@example.com', 'name': 'Jane Doe',
                             'telephone': '987-654-3210'}


def test_update_user_missing_data(client):
    token = create_jwt_token("create", 'admin')
    headers = {'Authorization': token, 'Content-Type': 'application/json'}
    data = {
        "email"    : "example@example.com",
        "name"     : "John Doe",
        "telephone": "123-456-7890"
    }
    response = client.post('/new', headers=headers, json=data)

    token = create_jwt_token("update", 'admin')
    headers = {'Authorization': token, 'Content-Type': 'application/json'}
    data = {
        "name"     : "Jane Doe",
    }
    response = client.put('/user/example@example.com', headers=headers, json=data)
    assert response.status_code == 400
    assert response.json == {'error': 'Missing data'}


def test_update_user_no_auth(client):
    token = create_jwt_token("create", 'admin')
    headers = {'Authorization': token, 'Content-Type': 'application/json'}
    data = {
        "email"    : "example@example.com",
        "name"     : "John Doe",
        "telephone": "123-456-7890"
    }
    response = client.post('/new', headers=headers, json=data)
    assert response.status_code == 200
    assert response.json == {'message': 'User created'}

    token = create_jwt_token("update", 'user')
    headers = {'Authorization': token, 'Content-Type': 'application/json'}
    data = {
        "name"     : "Jane Doe",
        "telephone": "987-654-3210"
    }
    response = client.put('/user/example@example.com', headers=headers, json=data)
    assert response.status_code == 403


def test_delete_user(client):
    token = create_jwt_token("delete", 'admin')
    headers = {'Authorization': token}
    response = client.delete('/user/example@example.com', headers=headers)
    assert response.status_code == 200
    assert response.json == {'message': 'User deleted'}


def test_delete_user_no_auth(client):
    token = create_jwt_token("delete", 'user')
    headers = {'Authorization': token}
    response = client.delete('/user/example@example.com', headers=headers)
    assert response.status_code == 403
