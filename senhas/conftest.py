def pytest_configure(config):
    config.addinivalue_line(
        "markers", "caracteresconfusos: mark test for removing confusing characters"
    )
    config.addinivalue_line(
        "markers", "error: mark test for invalid cases"
    )
