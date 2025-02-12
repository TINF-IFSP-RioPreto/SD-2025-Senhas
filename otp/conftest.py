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
