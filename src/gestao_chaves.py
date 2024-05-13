#gestao_chaves.py
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def criar_kdf(salt=None):
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf, salt

def gerar_par_chaves(senha):
    if not isinstance(senha, bytes):
        raise ValueError("Senha must be bytes")
    
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    chave_publica = chave_privada.public_key()

    # Uso da função criar_kdf para derivar a chave de criptografia a partir da senha
    kdf, salt = criar_kdf()  # Cria o KDF e obtém o salt

    # Criptografia da chave privada usando a chave derivada
    chave_privada_criptografada = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(kdf.derive(senha))
    )

    # Serialização da chave pública
    chave_publica_serializada = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return chave_privada_criptografada, chave_publica_serializada, salt  # Retorna as chaves e o salt
      
def exportar_chave_publica(chave_publica, nome_arquivo):
    with open(nome_arquivo, 'wb') as arquivo:
        arquivo.write(chave_publica)
        

def exportar_chave_privada(chave_privada, nome_arquivo, salt):
    with open(nome_arquivo, 'wb') as arquivo:
        arquivo.write(salt)  # Salvar o salt no arquivo
        arquivo.write(chave_privada)
        
def importar_chave_publica(nome_arquivo):
    with open(nome_arquivo, 'rb') as arquivo:
        chave_publica = serialization.load_pem_public_key(
            arquivo.read(),
            backend=default_backend()
        )
    return chave_publica

def importar_chave_privada(nome_arquivo, senha):
    with open(nome_arquivo, 'rb') as arquivo:
        salt = arquivo.read(16)  # Read the salt first
        encrypted_key = arquivo.read()  # Then read the encrypted key
        
    # Recreate the KDF with the exact salt used during encryption
    kdf, _ = criar_kdf(salt)
    
    try:
        chave_privada = serialization.load_pem_private_key(
            encrypted_key,
            password=kdf.derive(senha),
            backend=default_backend()
        )
        print("Key successfully decrypted and loaded.")
        return chave_privada
    except Exception as e:
        print(f"Failed to decrypt or load the key: {str(e)}")
        return str(e)
    
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

