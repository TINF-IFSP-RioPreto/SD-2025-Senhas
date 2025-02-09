import string
import unittest

from senhas import GerarSenhaAleatoria, GerarSenhaFrase, ValidarSenha


class TestGerarSenhaAleatoria(unittest.TestCase):

    def test_default_parameters(self):
        senha = GerarSenhaAleatoria()
        self.assertEqual(len(senha), 10)
        self.assertTrue(any(c.isupper() for c in senha))
        self.assertTrue(any(c.islower() for c in senha))
        self.assertTrue(any(c.isdigit() for c in senha))
        self.assertTrue(any(c in string.punctuation for c in senha))

    def test_custom_length(self):
        senha = GerarSenhaAleatoria(tamanho=15)
        self.assertEqual(len(senha), 15)

    def test_no_uppercase(self):
        senha = GerarSenhaAleatoria(maisculas=False)
        self.assertTrue(all(c.islower() or c.isdigit() or c in string.punctuation for c in senha))

    def test_no_lowercase(self):
        senha = GerarSenhaAleatoria(minusculas=False)
        self.assertTrue(all(c.isupper() or c.isdigit() or c in string.punctuation for c in senha))

    def test_no_digits(self):
        senha = GerarSenhaAleatoria(digitos=False)
        self.assertTrue(all(c.isalpha() or c in string.punctuation for c in senha))

    def test_no_symbols(self):
        senha = GerarSenhaAleatoria(simbolos=False)
        self.assertTrue(all(c.isalnum() for c in senha))

    def test_remove_confusos(self):
        senha = GerarSenhaAleatoria(remove_confusos=True)
        self.assertTrue(all(c not in 'IOl01' for c in senha))


class TestGerarSenhaFrase(unittest.TestCase):

    def setUp(self):
        # Create a mock palavras.txt file for testing
        with open("palavras.txt", 'w') as arquivo:
            arquivo.write("apple\nbanana\ncherry\ncoconut\ndate\n")

    def tearDown(self):
        # Remove the mock palavras.txt file after testing
        import os
        os.remove("palavras.txt")

    def test_default_parameters(self):
        senha = GerarSenhaFrase()
        self.assertEqual(len(senha.split('-')), 4)

    def test_custom_num_palavras(self):
        senha = GerarSenhaFrase(num_palavras=3)
        self.assertEqual(len(senha.split('-')), 3)

    def test_palavras_completas_false(self):
        senha = GerarSenhaFrase(palavras_completas=False)
        self.assertTrue(all(len(palavra) <= 4 for palavra in senha.split('-')))

    def test_custom_separador(self):
        senha = GerarSenhaFrase(separador='_')
        self.assertTrue('_' in senha)

    def test_maiuscula(self):
        senha = GerarSenhaFrase(maiuscula=True)
        self.assertTrue(any(palavra.isupper() for palavra in senha.split('-')))

    def test_invalid_num_palavras(self):
        senha = GerarSenhaFrase(num_palavras=0)
        self.assertIsNone(senha)

class TestValidarSenha(unittest.TestCase):

    def test_valid_password(self):
        self.assertTrue(ValidarSenha("Abc123!?", tamanho=8, maisculas=True, minusculas=True, digitos=True, simbolos=True))

    def test_short_password(self):
        self.assertFalse(ValidarSenha("Abc12!", tamanho=8, maisculas=True, minusculas=True, digitos=True, simbolos=True))

    def test_no_uppercase(self):
        self.assertFalse(ValidarSenha("abc123!?", tamanho=8, maisculas=True, minusculas=True, digitos=True, simbolos=True))

    def test_no_lowercase(self):
        self.assertFalse(ValidarSenha("ABC123!?", tamanho=8, maisculas=True, minusculas=True, digitos=True, simbolos=True))

    def test_no_digits(self):
        self.assertFalse(ValidarSenha("Abcdef!?", tamanho=8, maisculas=True, minusculas=True, digitos=True, simbolos=True))

    def test_no_symbols(self):
        self.assertFalse(ValidarSenha("Abc12345", tamanho=8, maisculas=True, minusculas=True, digitos=True, simbolos=True))


if __name__ == '__main__':
    unittest.main()
