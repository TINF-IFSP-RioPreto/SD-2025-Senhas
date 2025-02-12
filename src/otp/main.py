from io import BytesIO

import requests
from PIL import Image

from src.otp import criar_banco, criar_usuario, login

if __name__ == '__main__':
    # conn = sqlite3.connect("usuarios.db")
    conexao = criar_banco()

    email_usuario = input("Qual o email do usuário? ")
    senha_usuario = input("Qual a senha? ")
    usar_otp = True if input("Usa 2FA? ").lower()[0] == 's' else False

    novo_usuario = criar_usuario(conexao, email_usuario, senha_usuario, usar_otp)

    if novo_usuario is None:
        print(f"Usuário com email {email_usuario} já existe")
    else:
        segredo_otp, uri_otp, codigos_reserva = novo_usuario
        if segredo_otp:
            print("Usuario criado com 2FA")
            print(f"Segredo OTP: {segredo_otp}")
            print(f"URI para configuracao do autenticador: {uri_otp}")
            print("Códigos 2FA de reserva:")
            for codigo in codigos_reserva:
                print(f"  - {codigo}")
            url = f"https://quickchart.io/chart?cht=qr&chs=300x300&chl={uri_otp}"
            r = requests.get(url)
            if r.status_code == requests.codes.ok:
                print("QR-Code de conguracao salvo em 'qrcode.png'")
                Image.open(BytesIO(r.content)).save("qrcode.png")
            else:
                print("Erro ao gerar e salvar o QR-Code de configuracao")
        else:
            print("Usuario criado sem 2FA")

    senha_usuario = input("Digite a senha para verificar o login: ")
    if usar_otp:
        codigo_otp = input("Digite o código de autenticação 2FA: ")
        autenticado = login(conexao, email_usuario, senha_usuario, codigo_otp)
    else:
        autenticado = login(conexao, email_usuario, senha_usuario)

    if autenticado:
        print("Usuário autenticado")
    else:
        print("Falha na autenticação")
