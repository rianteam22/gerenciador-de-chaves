from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

def criptografar_com_chave_publica(arquivo_entrada, chave_publica_path):
    # Verifica se o arquivo de entrada e a chave pública existem
    if not os.path.exists(arquivo_entrada):
        raise FileNotFoundError(f"O arquivo de entrada {arquivo_entrada} não foi encontrado.")
    if not os.path.exists(chave_publica_path):
        raise FileNotFoundError(f"O arquivo da chave pública {chave_publica_path} não foi encontrado.")

    try:
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
    except Exception as e:
        raise Exception(f"Erro ao criptografar o arquivo: {str(e)}")

def descriptografar_com_chave_privada(arquivo_entrada, chave_privada_path, senha):
    # Verifica se o arquivo de entrada e a chave privada existem
    if not os.path.exists(arquivo_entrada):
        raise FileNotFoundError(f"O arquivo de entrada {arquivo_entrada} não foi encontrado.")
    if not os.path.exists(chave_privada_path):
        raise FileNotFoundError(f"O arquivo da chave privada {chave_privada_path} não foi encontrado.")

    try:
        with open(arquivo_entrada, 'rb') as file:
            ciphertext = file.read()

        with open(chave_privada_path, 'rb') as key_file:
            salt = key_file.read(16)
            encripted_key = key_file.read()

        from gestao_chaves import criar_kdf
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
    except Exception as e:
        raise Exception(f"Erro ao descriptografar o arquivo: {str(e)}")

