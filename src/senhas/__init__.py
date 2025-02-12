import re
import secrets
import string
from typing import Optional


def gerar_senha_aleatoria(tamanho: int = 10,
                          maiusculas: bool = True,
                          minusculas: bool = True,
                          digitos: bool = True,
                          simbolos: bool = True,
                          remove_confusos: bool = True) -> Optional[str]:
    categorias = {
        'maiusculas': 'ABCDEFGHJKLMNPQRSTUVWXYZ' if remove_confusos else string.ascii_uppercase,
        'minusculas': 'abcdefghjkmnpqrstuvwxyz' if remove_confusos else string.ascii_lowercase,
        'digitos'   : '23456789' if remove_confusos else string.digits,
        'simbolos'  : string.punctuation
    }

    categorias_ativas = {k: v for k, v in categorias.items() if locals()[k]}

    if not categorias_ativas or tamanho < len(categorias_ativas):
        return None

    rng = secrets.SystemRandom()

    # Seleciona pelo menos 1 caractere de cada categoria escolhida
    senha = [secrets.choice(chars) for chars in categorias_ativas.values()]

    # Completa a senha com caracteres aleatórios das categorias escolhidas
    todos_caracteres = ''.join(categorias_ativas.values())
    senha += rng.choices(todos_caracteres, k=tamanho - len(senha))

    # Shuffle to randomize order
    rng.shuffle(senha)

    return ''.join(senha)


def gerar_senha_frase(num_palavras: int = 4,
                      palavras_completas: bool = True,
                      separador: str = '-',
                      maiuscula: bool = False) -> str:
    if num_palavras < 1:
        return None

    lista = []
    with open("palavras.lst", 'r') as arquivo:
        for palavra in arquivo:
            lista.append(palavra.strip() if palavras_completas else palavra.strip()[:4])

    rng = secrets.SystemRandom()
    palavras = rng.choices(lista, k=num_palavras)
    if maiuscula:
        p = secrets.randbelow(num_palavras)
        palavras[p] = palavras[p].upper()

    return separador.join(palavras)


def validar_complexidade_senha(senha: str = None,
                               tamanho: int = 8,
                               maiusculas: bool = True,
                               minusculas: bool = True,
                               digitos: bool = True,
                               simbolos: bool = True) -> bool:
    valida = True
    valida = valida and (len(senha) >= tamanho)
    if maiusculas:
        valida = valida and (re.search(r'[A-Z]', senha) is not None)
    if minusculas:
        valida = valida and (re.search(r'[a-z]', senha) is not None)
    if digitos:
        valida = valida and (re.search(r'\d', senha) is not None)
    if simbolos:
        valida = valida and (re.search(r'\W', senha) is not None)

    return valida
