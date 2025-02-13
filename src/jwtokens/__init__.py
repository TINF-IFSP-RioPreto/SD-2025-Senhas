from time import time
from typing import Any, Dict, Optional

import jwt


def verifica_token_jwt(text: str = None,
                       sign_key: bytes = None) -> Dict[str, Any]:
    claims: Dict[str, Any] = {'valid': False}

    if sign_key is None:
        claims.update({'reason': "missing_key"})
        return claims

    try:
        payload = jwt.decode(jwt=text,
                             algorithms=['HS256'],
                             key=sign_key)
        claims.update({'valid' : True,
                       'sub'   : payload.get('sub', None),
                       'action': payload.get('action', None)})

        if 'iat' in payload:
            claims.update({'age': int(time()) - int(payload.get('iat'))})

        if 'extra_data' in payload:
            claims.update({'extra_data': payload.get('extra_data')})

    except jwt.ExpiredSignatureError as e:
        claims.update({'reason': "expired"})

    except jwt.InvalidTokenError as e:
        claims.update({'reason': "invalid"})

    except ValueError as e:
        claims.update({'reason': "valueerror"})

    return claims


def criar_token_jwt(sub: Any,
                    sign_key: bytes = None,
                    action: str = None,
                    expires_in: int = 600,
                    extra_data: Optional[Dict[str, str]] = None) -> Optional[str]:

    if sign_key is None or sub is None:
        return None  # Poderia gerar uma chave

    agora = int(time())
    try:
        claims = {
            'sub': str(sub),  # Assunto do token
            'iat': agora,  # Quando foi emitido
            'nbf': agora,  # Não é valido antes de
            'exp': agora + expires_in,  # Não é valido depois de
        }
    except TypeError:
        return None
    if action is not None:
        claims.update({'action': action.lower()})

    if extra_data is not None and isinstance(extra_data, dict):
        claims.update({'extra_data': extra_data})

    token = jwt.encode(payload=claims,
                       algorithm='HS256',
                       key=sign_key)
    return token
