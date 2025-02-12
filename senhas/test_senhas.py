import pytest
from string import ascii_uppercase, ascii_lowercase, digits, punctuation
from unittest.mock import patch, mock_open

from main import gerar_senha_aleatoria, gerar_senha_frase, validar_complexidade_senha

def pytest_configure(config):
    config.addinivalue_line(
        "markers", "caracteresconfusos: mark test for removing confusing characters"
    )
    config.addinivalue_line(
        "markers", "error: mark test for invalid cases"
    )

@pytest.fixture
def valid_test_passwords():
    """Fixture providing a set of valid passwords for different scenarios"""
    return {
        'all_categories': 'Testando123#$',
        'no_symbols': 'Testando1234',
        'no_digits': 'Testando#$ab',
        'minimal': 'Aa1#',
        'long': 'TestTestando123#$'
    }

@pytest.fixture
def mock_palavra_list():
    """Fixture providing mock word list data"""
    return "palavra1\npalavra2\npalavra3\npalavra4\npalavra5"

class TestGerarSenhaAleatoria:
    @pytest.mark.parametrize("tamanho", [8, 10, 15, 20])
    def test_diferentes_tamanhos(self, tamanho):
        senha = gerar_senha_aleatoria(tamanho=tamanho)
        assert len(senha) == tamanho

    @pytest.mark.parametrize("config", [
        {'maisculas': True, 'minusculas': False, 'digitos': False, 'simbolos': False},
        {'maisculas': False, 'minusculas': True, 'digitos': False, 'simbolos': False},
        {'maisculas': False, 'minusculas': False, 'digitos': True, 'simbolos': False},
        {'maisculas': False, 'minusculas': False, 'digitos': False, 'simbolos': True}
    ])
    def test_categorias_individuais(self, config):
        senha = gerar_senha_aleatoria(**config)
        for category, enabled in config.items():
            if enabled:
                if category == 'maisculas':
                    assert any(c in ascii_uppercase for c in senha)
                elif category == 'minusculas':
                    assert any(c in ascii_lowercase for c in senha)
                elif category == 'digitos':
                    assert any(c in digits for c in senha)
                elif category == 'simbolos':
                    assert any(c in punctuation for c in senha)

    @pytest.mark.caracteresconfusos
    def test_remove_confusos(self):
        senha = gerar_senha_aleatoria(remove_confusos=True)
        assert not any(c in 'Il1O0' for c in senha)

    @pytest.mark.error
    def test_casos_invalidos(self):
        assert gerar_senha_aleatoria(tamanho=2) is None
        assert gerar_senha_aleatoria(maisculas=False, minusculas=False,
                                     digitos=False, simbolos=False) is None

class TestGerarSenhaFrase:
    @pytest.mark.parametrize("num_palavras", [2, 3, 4, 5])
    def test_diferentes_numeros_palavras(self, num_palavras, mock_palavra_list):
        with patch("builtins.open", mock_open(read_data=mock_palavra_list)):
            senha = gerar_senha_frase(num_palavras=num_palavras)
            assert len(senha.split('-')) == num_palavras

    @pytest.mark.parametrize("separador", ['-', '_', '.', ' '])
    def test_diferentes_separadores(self, separador, mock_palavra_list):
        with patch("builtins.open", mock_open(read_data=mock_palavra_list)):
            senha = gerar_senha_frase(separador=separador)
            assert separador in senha


class TestValidarComplexidadeSenha:
    @pytest.mark.parametrize("senha,esperado", [
        ("Abc123#$", True),
        ("abc123#$", False),  # sem maiúsculas
        ("ABC123#$", False),  # sem minúsculas
        ("AbcDef#$", False),  # sem dígitos
        ("Abcd1234", False),  # sem símbolos
    ])
    def test_diferentes_complexidades(self, senha, esperado):
        assert validar_complexidade_senha(senha) is esperado

    def test_senha_valida(self, valid_test_passwords):
        assert validar_complexidade_senha(valid_test_passwords['all_categories']) is True

    @pytest.mark.parametrize("tamanho,esperado", [
        (8, True),
        (10, True),
        (12, True),
        (20, False)
    ])
    def test_diferentes_tamanhos_minimos(self, valid_test_passwords, tamanho, esperado):
        assert validar_complexidade_senha(
            valid_test_passwords['all_categories'],
            tamanho=tamanho
        ) is esperado
