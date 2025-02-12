import pytest
import sqlite3
import pyotp
import time
from main import criar_banco, criar_usuario, login, gerar_codigos_reserva


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "otp: mark test for OTP functionality"
    )
    config.addinivalue_line(
        "markers", "database: mark test for database constraints"
    )
    config.addinivalue_line(
        "markers", "security: mark test for security aspects"
    )

@pytest.fixture
def db_connection():
    """Fixture to provide a fresh database connection for each test"""
    conn = criar_banco('teste.db')
    yield conn
    conn.close()


@pytest.fixture
def sample_user(db_connection):
    """Fixture to create a sample user with OTP enabled"""
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
        hash = cursor.fetchone()[0]

        # Verify hash is sufficiently long (pbkdf2 hash)
        assert len(hash) > 50
        # Verify hash is not plaintext
        assert hash != password
        # Verify hash starts with expected algorithm identifier
        assert hash.startswith("scrypt:32768") or hash.startswith("pbkdf2:sha256")

