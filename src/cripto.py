from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from gestao_chaves import criar_kdf

def criptografar_com_chave_publica(arquivo_entrada, chave_publica_path):
    with open(arquivo_entrada, 'rb') as file:
        data = file.read()
    
    with open(chave_publica_path, 'rb') as key_file:
        chave_publica = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    
    ciphertext = chave_publica.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return ciphertext

def descriptografar_com_chave_privada(arquivo_entrada, chave_privada_path, senha):
    with open(arquivo_entrada, 'rb') as file:
        ciphertext = file.read()

    with open(chave_privada_path, 'rb') as key_file:
        salt = key_file.read(16)
        encripted_key = key_file.read()
        
    kdf, _ = criar_kdf(salt)
    chave_privada = serialization.load_pem_private_key(
        encripted_key,
        password=kdf.derive(senha),
        backend=default_backend()
    )
    
    original_data = chave_privada.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return original_data
