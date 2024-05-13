import unittest
import os
from cryptography.hazmat.primitives import serialization
import hashlib

import sys
import os

# Assuming your test script is in the 'testes' directory and your modules are in the 'src' directory.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))


from gestao_chaves import (criar_kdf, gerar_par_chaves, carregar_chave_publica,
                           carregar_chave_privada, exportar_chave_publica,
                           exportar_chave_privada, importar_chave_publica,
                           importar_chave_privada, listar_chaves, apagar_chave)

class TestGestaoChaves(unittest.TestCase):
    def test_criar_kdf(self):
        """Test if KDF and salt are created properly."""
        kdf, salt = criar_kdf()
        self.assertIsNotNone(kdf)
        self.assertEqual(len(salt), 16)  # Assuming salt should be 16 bytes

    def test_gerar_par_chaves(self):
        """Test key generation and encryption."""
        senha = 'test_password'
        hashed_password = hashlib.sha256(senha.encode()).digest()
        priv_key, pub_key, salt = gerar_par_chaves(hashed_password)
        self.assertIsNotNone(priv_key)
        self.assertIsNotNone(pub_key)
        self.assertEqual(len(salt), 16)

    def test_carregar_chave_publica(self):
        """Test loading a public key from a file."""
        # Mocking file operations would be required here
        pass

    def test_carregar_chave_privada(self):
        """Test loading a private key from a file with a password."""
        # Mocking file operations would be required here
        pass

    def test_exportar_chave_publica(self):
        """Test if public key is exported correctly."""
        # This would require mocking file operations
        pass

    def test_exportar_chave_privada(self):
        """Test if private key is exported correctly with encryption."""
        # This would require mocking file operations
        pass

    def test_importar_chave_publica(self):
        """Test public key import functionality."""
        # This would require mocking file operations
        pass

    def test_importar_chave_privada(self):
        """Test private key import functionality."""
        # This would require mocking file operations
        pass

    def test_listar_chaves(self):
        """Test listing of keys in a directory."""
        os.mkdir('test_keys')
        open('test_keys/test_key.pem', 'a').close()  # Create a dummy .pem file
        result = listar_chaves('test_keys')
        self.assertIn('test_key.pem', result)
        os.remove('test_keys/test_key.pem')  # Clean up
        os.rmdir('test_keys')

    def test_apagar_chave(self):
        """Test the deletion of a key file."""
        open('test_delete.pem', 'a').close()
        self.assertTrue(apagar_chave('test_delete.pem'))
        self.assertFalse(os.path.exists('test_delete.pem'))

if __name__ == '__main__':
    unittest.main()
