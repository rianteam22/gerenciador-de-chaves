import sys
import unittest
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from gestao_chaves import (
    gerar_par_chaves, exportar_chave_publica, exportar_chave_privada,
    importar_chave_publica, importar_chave_privada, listar_chaves, apagar_chave
)

class TestGestaoChaves(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.senha = b'senhaforte'
        cls.diretorio_chaves = 'test_keys'
        os.makedirs(cls.diretorio_chaves, exist_ok=True)

    def test_geracao_e_armazenamento_de_chaves(self):
        """
        Objetivo: Testar a geração de um par de chaves e seu armazenamento em arquivos.
        
        Processo: Gera um par de chaves usando uma senha pré-definida e verifica se as 
        chaves privada e pública são geradas corretamente. Em seguida, as chaves são 
        exportadas para arquivos e verifica-se a existência desses arquivos para confirmar 
        que foram salvos corretamente.
        """
        privada_criptografada, publica_serializada, salt = gerar_par_chaves(self.senha)
        self.assertIsNotNone(privada_criptografada)
        self.assertIsNotNone(publica_serializada)
        self.assertIsNotNone(salt)

        caminho_priv = os.path.join(self.diretorio_chaves, 'privada.pem')
        caminho_pub = os.path.join(self.diretorio_chaves, 'publica.pem')
        exportar_chave_privada(privada_criptografada, caminho_priv, salt)
        exportar_chave_publica(publica_serializada, caminho_pub)

        self.assertTrue(os.path.exists(caminho_priv))
        self.assertTrue(os.path.exists(caminho_pub))

    def test_importacao_de_chaves(self):
        """
        Objetivo: Testar a importação das chaves públicas e privadas a partir de arquivos.
        
        Processo: Importa as chaves a partir dos arquivos gerados anteriormente e verifica
        se os objetos de chave correspondentes são criados sem erros, garantindo que a importação
        foi bem-sucedida.
        """
        caminho_priv = os.path.join(self.diretorio_chaves, 'privada.pem')
        caminho_pub = os.path.join(self.diretorio_chaves, 'publica.pem')
        
        chave_publica = importar_chave_publica(caminho_pub)
        chave_privada = importar_chave_privada(caminho_priv, self.senha)

        self.assertIsNotNone(chave_publica)
        self.assertIsNotNone(chave_privada)

    def test_listar_e_apagar_chaves(self):
        """
        Objetivo: Testar a listagem e a exclusão de chaves armazenadas em um diretório.
        
        Processo: Lista todas as chaves no diretório de teste para verificar se as chaves
        esperadas estão presentes. Em seguida, remove uma das chaves e verifica se a chave
        foi efetivamente excluída do diretório.
        """
        chaves = listar_chaves(self.diretorio_chaves)
        self.assertIn('privada.pem', chaves)
        self.assertIn('publica.pem', chaves)

        apagar_chave(os.path.join(self.diretorio_chaves, 'publica.pem'))
        chaves_apos_remocao = listar_chaves(self.diretorio_chaves)
        self.assertNotIn('publica.pem', chaves_apos_remocao)

    @classmethod
    def tearDownClass(cls):
        # Limpeza: Remove todos os arquivos e diretórios criados
        for file in os.listdir(cls.diretorio_chaves):
            os.remove(os.path.join(cls.diretorio_chaves, file))
        os.rmdir(cls.diretorio_chaves)

if __name__ == '__main__':
    unittest.main()
