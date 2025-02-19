from pathlib import Path
from string import ascii_lowercase, ascii_uppercase, digits, punctuation

import pytest

from src.senhas import gerar_senha_aleatoria, gerar_senha_frase, validar_complexidade_senha


@pytest.fixture
def valid_test_passwords():
    """Fixture providing a set of valid passwords for different scenarios"""
    return {
        'all_categories': 'Testando123#$',
        'no_symbols'    : 'Testando1234',
        'no_digits'     : 'Testando#$ab',
        'minimal'       : 'Aa1#',
        'long'          : 'TestTestando123#$'
    }


class TestGerarSenhaAleatoria:
    @pytest.mark.parametrize("tamanho", [8, 10, 15, 20])
    def test_diferentes_tamanhos(self, tamanho):
        senha = gerar_senha_aleatoria(tamanho=tamanho)
        assert len(senha) == tamanho

    @pytest.mark.parametrize("config", [
        {'maiusculas': True, 'minusculas': False, 'digitos': False, 'simbolos': False},
        {'maiusculas': False, 'minusculas': True, 'digitos': False, 'simbolos': False},
        {'maiusculas': False, 'minusculas': False, 'digitos': True, 'simbolos': False},
        {'maiusculas': False, 'minusculas': False, 'digitos': False, 'simbolos': True}
    ])
    def test_categorias_individuais(self, config):
        senha = gerar_senha_aleatoria(**config)
        for category, enabled in config.items():
            if enabled:
                if category == 'maiusculas':
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
        assert gerar_senha_aleatoria(maiusculas=False, minusculas=False,
                                     digitos=False, simbolos=False) is None


class TestGerarSenhaFrase:
    @pytest.mark.parametrize("num_palavras", [2, 3, 4, 5])
    def test_diferentes_numeros_palavras(self, num_palavras):
        senha = gerar_senha_frase(num_palavras=num_palavras,
                                  arquivo=Path("palavras.lst"))
        assert len(senha.split('-')) == num_palavras

    def test_zero_palavras(self):
        senha = gerar_senha_frase(num_palavras=0,
                                  arquivo=Path("palavras.lst"))
        assert senha is None

    def test_lista_palvras_nao_existe(self):
        senha = gerar_senha_frase(num_palavras=2,
                                  arquivo=Path("error.lst"))
        assert senha is None

    def test_palavra_maiuscula(self):
        senha = gerar_senha_frase(num_palavras=3,
                                  arquivo=Path("palavras.lst"),
                                  maiuscula=True)
        c = any(char.isupper() for char in senha)
        assert c

    @pytest.mark.parametrize("separador", ['-', '_', '.', ' '])
    def test_diferentes_separadores(self, separador):
        senha = gerar_senha_frase(separador=separador,
                                  arquivo=Path("palavras.lst"))
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
