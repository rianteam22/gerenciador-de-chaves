#gestao_chaves.py
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def gerar_par_chaves(nome_arquivo_chave_privada, nome_arquivo_chave_publica):
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Definir o caminho da pasta keys dentro da pasta src
    base_path = os.path.dirname(__file__)  # Obtém o diretório onde o script está sendo executado
    keys_dir = os.path.join(base_path, 'keys')

    # Verificar se o diretório 'keys' existe, se não, criá-lo
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)

    # Caminhos completos para salvar as chaves
    chave_privada_path = os.path.join(keys_dir, nome_arquivo_chave_privada)
    chave_publica_path = os.path.join(keys_dir, nome_arquivo_chave_publica)

    # Salvar chave privada em formato PEM
    with open(chave_privada_path, 'wb') as chave_privada_arquivo:
        chave_privada_arquivo.write(
            chave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Salvar chave pública em formato PEM
    with open(chave_publica_path, 'wb') as chave_publica_arquivo:
        chave_publica_arquivo.write(
            chave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
def exportar_chave_publica(chave_publica, nome_arquivo):
    pem = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(nome_arquivo, 'wb') as arquivo:
        arquivo.write(pem)
        
def exportar_chave_privada(chave_privada, nome_arquivo, senha):
    senha_bytes = senha.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),
        iterations=100000,
        backend=default_backend()
    )
    pem = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(senha_bytes)
    )
    with open(nome_arquivo, 'wb') as arquivo:
        arquivo.write(pem)
        
def importar_chave_publica(nome_arquivo):
    with open(nome_arquivo, 'rb') as arquivo:
        chave_publica = serialization.load_pem_public_key(
            arquivo.read(),
            backend=default_backend()
        )
    return chave_publica

def importar_chave_privada(nome_arquivo, senha):
    senha_bytes = senha.encode()
    with open(nome_arquivo, 'rb') as arquivo:
        chave_privada = serialization.load_pem_private_key(
            arquivo.read(),
            password=senha_bytes,
            backend=default_backend()
        )
    return chave_privada
