import os

class Config:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    KEYS_DIR = os.path.join(DATA_DIR, 'keys')
    ENCRYPTED_FILES_DIR = os.path.join(DATA_DIR, 'arquivos_criptografados')

    @staticmethod
    def ensure_dir(directory):
        """Ensure the directory exists, create if it doesn't."""
        os.makedirs(directory, exist_ok=True)