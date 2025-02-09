from senhas import GerarSenhaAleatoria, GerarSenhaFrase, ValidarSenha
from werkzeug.security import check_password_hash, generate_password_hash

if __name__ == '__main__':
    t = int(input("Quantos caracteres na senha? "))
    ma = input("Letras maiusculas (S/N)? ").upper()
    mi = input("Letras minusculas (S/N)? ").upper()
    di = input("Digitos (S/N)? ").upper()
    si = input("Simbolos (S/N)? ").upper()
    rc = input("Remover simbolos que podem confundir (S/N)? ").upper()

    senha = GerarSenhaAleatoria(tamanho=t,
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

    senha = GerarSenhaFrase(num_palavras=t,
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

    teste = ValidarSenha(senha,
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
