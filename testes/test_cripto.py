import unittest
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from cripto import criptografar_com_chave_publica, descriptografar_com_chave_privada
from gestao_chaves import gerar_par_chaves, exportar_chave_publica, exportar_chave_privada

class TestCriptoFunctions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_dir = 'test_keys'
        os.makedirs(cls.test_dir, exist_ok=True)
        
        cls.senha = b'senhadeteste123'
        cls.private_key_path = os.path.join(cls.test_dir, 'test_private_key.pem')
        cls.public_key_path = os.path.join(cls.test_dir, 'test_public_key.pem')
        privada_criptografada, publica_serializada, salt = gerar_par_chaves(cls.senha)
        exportar_chave_privada(privada_criptografada, cls.private_key_path, salt)
        exportar_chave_publica(publica_serializada, cls.public_key_path)
        
        cls.test_file_path = os.path.join(cls.test_dir, 'test_file.txt')
        with open(cls.test_file_path, 'wb') as f:
            f.write(b"Este e um arquivo de teste para criptografia e descriptografia.")

    def test_encryption_and_decryption(self):
        """
        Objetivo: Testar a criptografia de um arquivo usando a chave pública e a subsequente 
        descriptografia usando a chave privada correspondente.
        
        Processo: 
            Criptografa o conteúdo de um arquivo de teste usando a chave pública e verifica
        se os dados criptografados não são nulos.
        
            Salva os dados criptografados em um arquivo e, em seguida, descriptografa esse arquivo 
        usando a chave privada.
        
            Compara os dados descriptografados com o conteúdo original do arquivo de teste para 
        garantir que a descriptografia foi bem-sucedida e que os dados são idênticos aos originais.
        """
        encrypted_data = criptografar_com_chave_publica(self.test_file_path, self.public_key_path)
        self.assertIsNotNone(encrypted_data, "A criptografia retornou None, dados criptografados esperados.")
        
        encrypted_file_path = os.path.join(self.test_dir, 'encrypted_file.enc')
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
        
        decrypted_data = descriptografar_com_chave_privada(encrypted_file_path, self.private_key_path, self.senha)
        self.assertIsNotNone(decrypted_data, "A descriptografia retornou None, dados descriptografados esperados.")
        
        with open(self.test_file_path, 'rb') as f:
            original_data = f.read()
        self.assertEqual(decrypted_data, original_data, "Os dados descriptografados não correspondem ao original.")

    @classmethod
    def tearDownClass(cls):
        for filename in os.listdir(cls.test_dir):
            os.remove(os.path.join(cls.test_dir, filename))
        os.rmdir(cls.test_dir)

if __name__ == '__main__':
    unittest.main()
