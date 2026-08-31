from cryptography.fernet import Fernet
from app.core.config import settings

class CryptoService:
    def __init__(self):
        if not settings.MASTER_KEY:
            raise ValueError("MASTER_KEY missing")
        self.fernet = Fernet(settings.MASTER_KEY.encode())

    def encrypt(self, plaintext: str) -> str:
        if not plaintext:
            return plaintext
        return self.fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        if not ciphertext:
            return ciphertext
        return self.fernet.decrypt(ciphertext.encode()).decode()

crypto_service = CryptoService()
