import pathlib
import sys


def pytest_configure(config):
    project_root = pathlib.Path(__file__).parent.parent
    sys.path.insert(0, str(project_root / "src"))  # Add "src" to Python path

    config.addinivalue_line("markers", "otp: mark test for OTP functionality")
    config.addinivalue_line("markers", "database: mark test for database constraints")
    config.addinivalue_line("markers", "security: mark test for security aspects")
    config.addinivalue_line("markers",
                            "caracteresconfusos: mark test for removing confusing characters")
    config.addinivalue_line("markers", "error: mark test for invalid cases")
