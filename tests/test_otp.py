import sqlite3
import time

import pyotp
import pytest

from src.otp import criar_banco, criar_usuario, gerar_codigos_reserva, login


@pytest.fixture
def db_connection():
    """Fixture para criar uma conexão nova de banco de dados para cada teste"""
    conn = criar_banco('teste.db')
    yield conn
    conn.close()


@pytest.fixture
def sample_user(db_connection):
    """Fixture para criar um usuário com OTP ativado"""
    email = "test@example.com"
    password = "password123"
    otp_secret, _, backup_codes = criar_usuario(db_connection, email, password, use_otp=True)
    return {
        "email"       : email,
        "password"    : password,
        "otp_secret"  : otp_secret,
        "backup_codes": backup_codes
    }


# Parametrized test for invalid email formats
@pytest.mark.parametrize("invalid_email", [
    "",
    None
])
def test_criar_usuario_invalid_email(db_connection, invalid_email):
    """Test user creation with various invalid email formats"""
    usuario = criar_usuario(db_connection, invalid_email, "password123")
    assert usuario is None


# Parametrized test for invalid passwords
@pytest.mark.parametrize("invalid_password", [
    "",
    None
])
def test_criar_usuario_invalid_password(db_connection, invalid_password):
    """Test user creation with various invalid password formats"""
    usuario = criar_usuario(db_connection, "test@example.com", invalid_password)
    assert usuario is None


def test_criar_usuario_existing_email(db_connection):
    """Test duplicate user creation"""
    criar_usuario(db_connection, "test@example.com", "password123")
    usuario = criar_usuario(db_connection, "test@example.com", "password123")
    assert usuario is None


def test_login_no_user(db_connection):
    """Test login for non existing user"""
    criar_usuario(db_connection, "test@example.com", "password123")
    assert not login(db_connection, "test2@example.com", "password123")


def test_login_wrong_password(db_connection):
    """Test login for non existing user"""
    criar_usuario(db_connection, "test@example.com", "password123")
    assert not login(db_connection, "test@example.com", "password")


def test_login_success_no_otp(db_connection):
    """Test login for non existing user"""
    criar_usuario(db_connection, "test@example.com", "password123")
    assert login(db_connection, "test@example.com", "password123")


def test_gerar_codigos_reserva_no_user(db_connection, sample_user):
    backup_codes = gerar_codigos_reserva(db_connection, "usuario@dominio.tld",
                                         sample_user['password'])
    assert backup_codes is None


def test_gerar_codigos_reserva_wrong_password(db_connection, sample_user):
    backup_codes = gerar_codigos_reserva(db_connection, sample_user['email'], "password")
    assert backup_codes is None


def test_gerar_codigos_reserva_no_otp(db_connection):
    criar_usuario(db_connection, "test@example.com", "password123")
    backup_codes = gerar_codigos_reserva(db_connection, "test@example.com", "password123")
    assert backup_codes is None


# Test group for OTP functionality
@pytest.mark.otp
class TestOTPFunctionality:
    def test_otp_generation(self, sample_user, db_connection):
        """Test OTP code generation and validation"""
        totp = pyotp.TOTP(sample_user["otp_secret"])
        assert login(db_connection, sample_user["email"],
                     sample_user["password"], totp.now())

    @pytest.mark.parametrize("time_offset", [-60, -30, 30, 60])
    def test_otp_time_window(self, sample_user, db_connection, time_offset):
        """Test OTP validation within different time windows"""
        totp = pyotp.TOTP(sample_user["otp_secret"])
        assert not login(db_connection, sample_user["email"],
                         sample_user["password"],
                         totp.at(int(time.time()) + time_offset))

    def test_backup_codes(self, sample_user, db_connection):
        """Test all backup codes for a user"""
        for code in sample_user["backup_codes"]:
            assert login(db_connection, sample_user["email"],
                         sample_user["password"], code)
            # Second attempt should fail
            assert not login(db_connection, sample_user["email"],
                             sample_user["password"], code)


# Test database constraints
@pytest.mark.database
class TestDatabaseConstraints:
    def test_unique_email(self, db_connection):
        """Test email uniqueness constraint"""
        criar_usuario(db_connection, "test@example.com", "password123")
        with pytest.raises(sqlite3.IntegrityError):
            db_connection.execute(
                "INSERT INTO usuarios (email, senha_hash) VALUES (?, ?)",
                ("test@example.com", "hash")
            )

    def test_cascade_delete(self, db_connection, sample_user):
        """Test cascade delete of backup codes when user is deleted"""
        cursor = db_connection.cursor()

        # Get user ID
        cursor.execute("SELECT id FROM usuarios WHERE email = ?",
                       (sample_user["email"],))
        user_id = cursor.fetchone()[0]

        # Delete user
        cursor.execute("DELETE FROM usuarios WHERE id = ?", (user_id,))
        db_connection.commit()

        # Check backup codes were deleted
        cursor.execute("SELECT COUNT(*) FROM backupkeys WHERE user_id = ?",
                       (user_id,))
        assert cursor.fetchone()[0] == 0


@pytest.mark.security
class TestSecurity:
    def test_password_hash_strength(self, db_connection):
        """Test password hash strength"""
        email = "security@example.com"
        password = "password123"
        criar_usuario(db_connection, email, password)

        cursor = db_connection.cursor()
        cursor.execute("SELECT senha_hash FROM usuarios WHERE email = ?", (email,))
        passwd_hash = cursor.fetchone()[0]

        # Verify hash is sufficiently long (pbkdf2 hash)
        assert len(passwd_hash) > 50
        # Verify hash is not plaintext
        assert passwd_hash != password
        # Verify hash starts with expected algorithm identifier
        assert passwd_hash.startswith("scrypt:32768") or passwd_hash.startswith("pbkdf2:sha256")
