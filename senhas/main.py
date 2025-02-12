import re
import secrets
import string
from typing import Optional
from werkzeug.security import check_password_hash, generate_password_hash


def gerar_senha_aleatoria(tamanho: int = 10,
                          maisculas: bool = True,
                          minusculas: bool = True,
                          digitos: bool = True,
                          simbolos: bool = True,
                          remove_confusos: bool = True) -> Optional[str]:
    categorias = {
        'maisculas' : 'ABCDEFGHJKLMNPQRSTUVWXYZ' if remove_confusos else string.ascii_uppercase,
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
                               maisculas: bool = True,
                               minusculas: bool = True,
                               digitos: bool = True,
                               simbolos: bool = True) -> bool:
    valida = True
    valida = valida and (len(senha) >= tamanho)
    if maisculas:
        valida = valida and (re.search(r'[A-Z]', senha) is not None)
    if minusculas:
        valida = valida and (re.search(r'[a-z]', senha) is not None)
    if digitos:
        valida = valida and (re.search(r'\d', senha) is not None)
    if simbolos:
        valida = valida and (re.search(r'\W', senha) is not None)

    return valida


if __name__ == '__main__':
    t = int(input("Quantos caracteres na senha? "))
    ma = input("Letras maiusculas (S/N)? ").upper()
    mi = input("Letras minusculas (S/N)? ").upper()
    di = input("Digitos (S/N)? ").upper()
    si = input("Simbolos (S/N)? ").upper()
    rc = input("Remover simbolos que podem confundir (S/N)? ").upper()

    senha = gerar_senha_aleatoria(tamanho=t,
                                  maisculas=True if ma == 'S' else False,
                                  minusculas=True if mi == 'S' else False,
                                  digitos=True if di == 'S' else False,
                                  simbolos=True if si == 'S' else False,
                                  remove_confusos=True if rc == 'S' else False)
    if senha is None:
        print("Impossivel criar sua senha")
    else:
        print(f"A sua senha vai ser: {senha}")

    t = int(input("Quantas palavras na senha? "))
    co = input("Palavras completas (S/N)? ").upper()
    ma = input("Letras maiusculas (S/N)? ").upper()
    se = input("Qual separador usar? ")[:1]

    senha = gerar_senha_frase(num_palavras=t,
                              palavras_completas=True if co == 'S' else False,
                              separador=se,
                              maiuscula=True if ma == 'S' else False)

    if senha is None:
        print("Impossivel criar sua senha")
    else:
        print(f"A sua senha vai ser: {senha}")

    senha = input("Digite uma senha para testar: ")
    t = int(input("Tamanho? "))
    ma = input("Letras maiusculas (S/N)? ").upper()
    mi = input("Letras minusculas (S/N)? ").upper()
    di = input("Digitos (S/N)? ").upper()
    si = input("Simbolos (S/N)? ").upper()

    teste = validar_complexidade_senha(senha,
                                       tamanho=t,
                                       maisculas=True if ma == 'S' else False,
                                       minusculas=True if mi == 'S' else False,
                                       digitos=True if di == 'S' else False,
                                       simbolos=True if si == 'S' else False)

    if teste:
        print("A sua senha passa na complexidade desejada")
    else:
        print("Sua senha é um lixo")

    cifrada = generate_password_hash(senha)
    print(f"A sua senha cifrada é: {cifrada}")

    senha = input("Digite de novo a senha: ")

    igual = check_password_hash(cifrada, senha)
    if igual:
        print("As senhas sao iguais")
    else:
        print("As senhas sao diferentes")
