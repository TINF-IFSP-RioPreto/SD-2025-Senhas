import re
import secrets
import string
from pathlib import Path
from typing import Optional


def gerar_senha_aleatoria(tamanho: int = 10,
                          maiusculas: bool = True,
                          minusculas: bool = True,
                          digitos: bool = True,
                          simbolos: bool = True,
                          remove_confusos: bool = True) -> Optional[str]:
    """
    Gera uma senha aleatória que pode conter letras maiúsculas, minúsculas, dígitos e símbolos

    - Comeca selecionando um caracter de cada categoria selecionada
    - Continua selecionando caracteres aleatórios da união das categorias selecionadas até
      atingir o tamanho desejado

    Args:
        tamanho (int): O tamanho da senha a ser gerada (default: 8).
        maiusculas (bool): Utiliza letras maiúsculas (default: True).
        minusculas (bool): Utiliza letras minúsculas (default: True).
        digitos (bool): Utiliza digitos decimais (default: True).
        simbolos (bool): Utiliza símbolos diversos (default: True).
        remove_confusos (bool): Remove caracteres Iil1O0 (default: True).
    Returns:
        str: A senha gerada aleatoriamente.

    """
    categorias = {
        'maiusculas': 'ABCDEFGHJKLMNPQRSTUVWXYZ' if remove_confusos else string.ascii_uppercase,
        'minusculas': 'abcdefghjkmnopqrstuvwxyz' if remove_confusos else string.ascii_lowercase,
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
                      maiuscula: bool = False,
                      arquivo: Path = Path("palavras.lst")) -> Optional[str]:
    """
    Gera uma senha forte selecionando um conjunto de palavras aleatórias de uma lista.

    Args:
        num_palavras (int): Número de palavras (mínimo 1) a serem incluídas na senha (default: 4).
        palavras_completas (bool): Se True, usa palavras inteiras; se False, usa apenas os primeiros
                                   4 caracteres de cada palavra (default: True).
        separador (str): Caractere usado para separar as palavras na senha (default: '-').
        maiuscula (bool): Se True, alguma palavras será convertida para maiúsculas (default: False).
        arquivo (Path): Caminho do arquivo de palavras a ser usado (default: 'palavras.lst').

    Returns:
        str: A senha gerada como uma string, separada pelo caractere especificado, ou None se
             `num_palavras` for menor que 1 ou se o `arquivo` não existir
    """
    if num_palavras < 1:
        return None

    if not arquivo.is_file():
        return None

    lista = []
    with open(arquivo, 'r') as arquivo:
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
    """
    Valida a complexidade de uma senha de acordo com critérios especificados.

    A função verifica se a senha atende a requisitos mínimos de comprimento e presença
    de diferentes tipos de caracteres (maiúsculas, minúsculas, dígitos e símbolos).

    Args:
        senha (str): A senha a ser validada.
        tamanho (int): Comprimento mínimo exigido para a senha (default: 8).
        maiusculas (bool): Se True, exige ao menos uma letra maiúscula (default: True).
        minusculas (bool): Se True, exige ao menos uma letra minúscula (default: True).
        digitos (bool): Se True, exige ao menos um número (default: True).
        simbolos (bool): Se True, exige ao menos um caractere não alfanumérico (default: True).

    Returns:
        bool: True se a senha atender a todos os critérios especificados, False caso contrário.
    """
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
