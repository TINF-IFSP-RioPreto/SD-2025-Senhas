from time import sleep

import jwt
import pytest

from src.jwtokens import criar_token_jwt, verifica_token_jwt


# Test fixtures
@pytest.fixture
def sign_key():
    return b'test_secret_key'


@pytest.fixture
def sample_payload():
    return {
        'sub'       : 'test_user',
        'action'    : 'login',
        'extra_data': {'role': 'admin'}
    }


# Tests for criar_token_jwt
def test_criar_token_jwt_success(sign_key, sample_payload):
    token = criar_token_jwt(
        sub=sample_payload['sub'],
        sign_key=sign_key,
        action=sample_payload['action'],
        extra_data=sample_payload['extra_data']
    )
    assert token is not None
    # Verify token can be decoded
    decoded = jwt.decode(token, sign_key, algorithms=['HS256'])
    assert decoded['sub'] == sample_payload['sub']
    assert decoded['action'] == sample_payload['action']
    assert decoded['extra_data'] == sample_payload['extra_data']


def test_criar_token_jwt_no_key():
    token = criar_token_jwt(sub='test_user', sign_key=None)
    assert token is None


def test_criar_token_jwt_invalid_sub():
    token = criar_token_jwt(sub=None, sign_key=b'key')
    assert token is None


def test_criar_token_jwt_expiration(sign_key):
    expires_in = 2
    token = criar_token_jwt(sub='test_user', sign_key=sign_key, expires_in=expires_in)
    assert token is not None

    # Token should be valid initially
    decoded = jwt.decode(token, sign_key, algorithms=['HS256'])
    assert decoded['exp'] - decoded['iat'] == expires_in

    # Wait for token to expire
    sleep(expires_in + 1)
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, sign_key, algorithms=['HS256'])


# Tests for verifica_token_jwt
def test_verifica_token_jwt_valid(sign_key):
    token = criar_token_jwt(sub='test_user', sign_key=sign_key)
    claims = verifica_token_jwt(token, sign_key)
    assert claims['valid'] is True
    assert claims['sub'] == 'test_user'
    assert 'age' in claims


def test_verifica_token_jwt_no_key():
    claims = verifica_token_jwt('some_token', sign_key=None)
    assert claims['valid'] is False
    assert claims['reason'] == 'missing_key'


def test_verifica_token_jwt_invalid_token(sign_key):
    claims = verifica_token_jwt('invalid_token', sign_key)
    assert claims['valid'] is False
    assert claims['reason'] == 'invalid'


def test_verifica_token_jwt_expired(sign_key):
    # Create token that's already expired
    token = criar_token_jwt(sub='test_user', sign_key=sign_key, expires_in=-1)
    claims = verifica_token_jwt(token, sign_key)
    assert claims['valid'] is False
    assert claims['reason'] == 'expired'


def test_verifica_token_jwt_with_extra_data(sign_key):
    extra_data = {'role': 'admin', 'permissions': ['read', 'write']}
    token = criar_token_jwt(
        sub='test_user',
        sign_key=sign_key,
        extra_data=extra_data
    )
    claims = verifica_token_jwt(token, sign_key)
    assert claims['valid'] is True
    assert claims['extra_data'] == extra_data


def test_verifica_token_jwt_action(sign_key):
    action = 'LOGIN'
    token = criar_token_jwt(sub='test_user', sign_key=sign_key, action=action)
    claims = verifica_token_jwt(token, sign_key)
    assert claims['valid'] is True
    assert claims['action'] == action.lower()
