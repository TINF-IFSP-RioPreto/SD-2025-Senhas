import secrets
import sqlite3
from io import BytesIO
from typing import List, Optional, Tuple

import pyotp
import requests
from PIL import Image
from werkzeug.security import check_password_hash, generate_password_hash


def criar_banco(filename: str = 'usuarios.db') -> sqlite3.Connection:
    """
        Cria o banco de dados, descartando os dodos se houver algum
    """
    conn = sqlite3.connect(filename)
    # Enable foreign key support
    conn.execute("PRAGMA foreign_keys = ON;")

    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS usuarios;")
    cursor.execute("""CREATE TABLE usuarios
                    (
                        id          INTEGER NOT NULL
                                    CONSTRAINT usuarios_pk PRIMARY KEY
                                    AUTOINCREMENT,
                        email       TEXT    NOT NULL,
                        senha_hash  text    NOT NULL,
                        use_otp     BOOLEAN NOT NULL DEFAULT 0,
                        otp_secret  TEXT
                    );""")
    cursor.execute("CREATE UNIQUE INDEX usuarios_email_uindex ON usuarios(email);")
    cursor.execute("DROP TABLE IF EXISTS backupkeys;")
    cursor.execute("""CREATE TABLE backupkeys
                    (
                        id          INTEGER NOT NULL
                                    CONSTRAINT backupkeys_pk PRIMARY KEY
                                    AUTOINCREMENT,
                        user_id     INTEGER NOT NULL
                                    CONSTRAINT backupkeys_usuarios_id_fk
                                    REFERENCES usuarios(id) ON DELETE CASCADE,
                        backup_code TEXT NOT NULL,
                        used        BOOLEAN NOT NULL DEFAULT 0
                    );""")
    cursor.execute("CREATE INDEX backupkeys_user_id_index ON backupkeys(user_id);")
    conn.commit()
    return conn


def criar_usuario(conn: sqlite3.Connection,
                  email: str = None,
                  senha: str = None,
                  use_otp: bool = False) -> Optional[Tuple[Optional[str],
                                                           Optional[str],
                                                           Optional[List[str]]]]:
    """
        Cria um novo usuário na base de dados.

        - O email é armazenado em letras minúsculas para garantir consistência.
        - A senha é armazenada como um hash usando `generate_password_hash()`.
        - Gera um segredo OTP usando `pyotp.random_base32()`.
        - Gera 5 códigos de backup de 6 caracteres cada, armazenando-os na tabela `backupkeys`
          em formato hash.
        - Retorna o segredo OTP e os códigos de backup em texto plano para o usuário.

        Arguments:
            conn (sqlite3.Connection): Conexão com o banco de dados SQLite.
            email (str): Email do usuário.
            senha (str): Senha em texto plano.
            use_otp (bool): O usuário vai utilizar 2FA (padrão False)

        Returns:
            None se o usuário já existir; Tuple[str, str, List[str]] contendo segredo OTP, URI
            para configuração do autenticador e lista de códigos de backup em texto plano se
            usuário tiver configurado 2FA.
    """
    if email is None or senha is None:
        return None

    if email.strip() == "" or senha.strip() == "":
        return None

    cursor = conn.cursor()

    cursor.execute("SELECT id "
                   "FROM usuarios "
                   "WHERE email = ?", (email.lower(),))
    if cursor.fetchone():
        return None

    senha_hash = generate_password_hash(senha)
    otp_secret = pyotp.random_base32() if use_otp else ""

    cursor.execute("INSERT INTO usuarios "
                   "(email, senha_hash, otp_secret, use_otp) "
                   "VALUES (?, ?, ?, ?)", (email.lower(), senha_hash, otp_secret, use_otp))

    conn.commit()

    if not use_otp:
        return None, None, None

    backup_codes = gerar_codigos_reserva(conn, email, senha, 5)
    otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=email.lower(),
                                                           issuer_name="Minha aplicação")

    return otp_secret, otp_uri, backup_codes


def login(conn: sqlite3.Connection,
          email: str,
          senha: str,
          otp: str = None) -> bool:
    """
    Verifica as credenciais do usuário para autenticação.

    - O email é convertido para letras minúsculas antes da busca no banco de dados.
    - A senha é validada usando `check_password_hash()`.
    - O código OTP é validado usando `totp.verify()`.
    - Caso o OTP falhe, verifica se o código fornecido corresponde a um código de backup não
      utilizado.
    - Se um código de backup for usado, ele é marcado como "usado" (`used = True`).

    Args:
        conn (sqlite3.Connection): Conexão com o banco de dados SQLite.
        email (str): Email do usuário.
        senha (str): Senha em texto plano.
        otp (str): Código OTP ou código de backup.

    Returns:
         bool: `True` se a autenticação for bem-sucedida, `False` caso contrário.
    """

    cur = conn.cursor()

    # Retrieve user data
    cur.execute("SELECT id, senha_hash, otp_secret, use_otp "
                "FROM usuarios "
                "WHERE email = ?", (email.lower(),))
    user = cur.fetchone()

    if not user:
        return False  # User not found

    user_id, senha_hash, otp_secret, use_otp = user

    # Check password
    if not check_password_hash(senha_hash, senha):
        return False

    # There is no OTP to check
    if not use_otp:
        return True

    # Verify OTP
    totp = pyotp.TOTP(otp_secret)
    if totp.verify(otp):
        return True

    # If OTP fails, check backup codes
    cur.execute("SELECT id, backup_code "
                "FROM backupkeys "
                "WHERE user_id = ? AND used = 0",
                (user_id,))
    backup_codes = cur.fetchall()

    if not backup_codes:  # Explicit check if no unused backup codes are available
        return False

    for backup_id, hashed_code in backup_codes:
        if check_password_hash(hashed_code, otp):
            # Remove the used backup code
            cur.execute("UPDATE backupkeys "
                        "SET used = 1 "
                        "WHERE id = ?", (backup_id,))
            conn.commit()
            return True

    return False  # If all checks fail


def gerar_codigos_reserva(conn: sqlite3.Connection,
                          email: str,
                          senha: str,
                          quantidade: int = 5) -> Optional[List[str]]:
    """
    Gera novos códigos de backup para um usuário autenticado.

    - O email é convertido para letras minúsculas antes da busca no banco de dados.
    - A senha é validada usando `check_password_hash()`.
    - Se a senha estiver correta, novos códigos de backup são gerados e armazenados no banco
      de dados.
    - Os códigos são armazenados na tabela `backupkeys` com `used = False` e retornados em
      texto plano.

    Args:
        conn (sqlite3.Connection): Conexão com o banco de dados SQLite.
        email (str): Email do usuário.
        senha (str): Senha em texto plano.
        quantidade (int): Número de códigos de backup que devem ser gerados (default: 5)

    Returns:
        Optional[List[str]]: Lista dos novos códigos de backup em texto plano, ou `None` se a
                             senha for inválida.
    """

    cur = conn.cursor()

    # Retrieve user data
    cur.execute("SELECT id, senha_hash, use_otp "
                "FROM usuarios "
                "WHERE email = ?", (email.lower(),))
    user = cur.fetchone()

    if not user:
        return None  # User not found

    user_id, senha_hash, use_otp = user

    # Verify password
    if not check_password_hash(senha_hash, senha):
        return None  # Invalid password

    #
    if not use_otp:
        return None

    # Generate new backup codes
    new_codes = ["".join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(6))
                 for _ in range(quantidade)]

    for code in new_codes:
        hashed_code = generate_password_hash(code)
        cur.execute("INSERT INTO backupkeys "
                    "(user_id, backup_code, used) "
                    "VALUES (?, ?, False)",
                    (user_id, hashed_code))

    conn.commit()
    return new_codes  # Return plaintext codes to the user


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
