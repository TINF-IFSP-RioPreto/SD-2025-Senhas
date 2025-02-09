import random
import re
import string


def GerarSenhaAleatoria(tamanho: int = 10,
                        maisculas: bool = True,
                        minusculas: bool = True,
                        digitos: bool = True,
                        simbolos: bool = True,
                        remove_confusos: bool = True) -> str:
    categorias = {
        'maisculas': 'ABCDEFGHJKLMNPRSTUVWXYZ' if remove_confusos else string.ascii_uppercase,
        'minusculas': 'abcdefghjkmnopqrstuvwxyz' if remove_confusos else string.ascii_lowercase,
        'digitos': '23456789' if remove_confusos else string.digits,
        'simbolos': string.punctuation
    }

    # Filter out disabled categories
    categorias_ativas = {k: v for k, v in categorias.items() if locals()[k]}

    if not categorias_ativas or tamanho < len(categorias_ativas):
        return None

    # Select at least one character from each chosen category
    senha = [random.choice(chars) for chars in categorias_ativas.values()]

    # Fill the rest of the password with random choices from all selected characters
    todos_caracteres = ''.join(categorias_ativas.values())
    senha += random.choices(todos_caracteres, k=tamanho - len(senha))

    # Shuffle to randomize order
    random.shuffle(senha)

    return ''.join(senha)


def GerarSenhaFrase(num_palavras: int = 4,
                    palavras_completas: bool = True,
                    separador: str = '-',
                    maiuscula: bool = False) -> str:
    if num_palavras < 1:
        return None

    lista = []
    with open("palavras.lst", 'r') as arquivo:
        for palavra in arquivo:
            lista.append(palavra.strip() if palavras_completas else palavra.strip()[:4])

    palavras = random.sample(lista, num_palavras)
    if maiuscula:
        p = random.randint(0, num_palavras - 1)
        palavras[p] = palavras[p].upper()

    return separador.join(palavras)


def ValidarSenha(senha: str = None,
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