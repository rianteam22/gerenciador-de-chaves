#gestao_chaves.py
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def gerar_par_chaves(nome_arquivo_chave_privada, nome_arquivo_chave_publica, senha):
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    chave_publica = chave_privada.public_key()  # Obter a chave pública a partir da chave privada
    senha_bytes = senha.encode()
    kdf, salt = criar_kdf(senha_bytes)
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
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(senha_bytes)
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

def carregar_chave_publica(nome_arquivo):
    with open(nome_arquivo, 'rb') as arquivo:
        chave_publica = serialization.load_pem_public_key(
            arquivo.read(),
            backend=default_backend()
        )
    return chave_publica

def carregar_chave_privada(nome_arquivo, senha):
    with open(nome_arquivo, 'rb') as arquivo:
        chave_privada = serialization.load_pem_private_key(
            arquivo.read(),
            password=senha.encode(),
            backend=default_backend()
        )
    return chave_privada
      
def exportar_chave_publica(chave_publica, nome_arquivo):
    pem = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(nome_arquivo, 'wb') as arquivo:
        arquivo.write(pem)
        
def criar_kdf(senha_bytes):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf, salt

def exportar_chave_privada(chave_privada, nome_arquivo, senha):
    senha_bytes = senha.encode()
    kdf, salt = criar_kdf(senha_bytes)
    pem = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(senha_bytes)
    )
    with open(nome_arquivo, 'wb') as arquivo:
        arquivo.write(salt)  # Salvar o salt no arquivo
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

def listar_chaves(diretorio_chaves, filtro=None):
    """Listar todas as chaves no diretório especificado, filtradas por um termo opcional."""
    try:
        chaves = [f for f in os.listdir(diretorio_chaves) if f.endswith('.pem')]
        if filtro:
            chaves = [f for f in chaves if filtro.lower() in f.lower()]
        return chaves
    except FileNotFoundError:
        print("Diretório não encontrado.")
        return []
def apagar_chave(nome_arquivo):
    """Apagar a chave especificada."""
    try:
        os.remove(nome_arquivo)
        return True
    except OSError as e:
        print(f"Erro ao apagar chave: {e}")
        return False

