from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
import time
import hashlib

class AESCipher:
    def __init__(self, master_key):
        self.master_key = self._derive_key(master_key)
        self.current_key = self.master_key
        self.key_expiry = time.time() + 3600  # Rotate keys every hour
        self.key_version = 1

    def _derive_key(self, key):
        """Derive 256-bit key from any input"""
        return hashlib.sha256(key.encode()).digest()

    def _rotate_key(self):
        """Generate new key based on master key + timestamp"""
        if time.time() > self.key_expiry:
            self.key_version += 1
            dynamic_seed = f"{self.master_key.hex()}{int(time.time()/3600)}"
            self.current_key = hashlib.sha256(dynamic_seed.encode()).digest()
            self.key_expiry = time.time() + 3600
            return True
        return False

    def encrypt(self, data):
        """Encrypt with key version prefix"""
        self._rotate_key()
        iv = os.urandom(16)
        cipher = AES.new(self.current_key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data.encode(), AES.block_size))
        payload = f"{self.key_version}:{base64.b64encode(iv + encrypted).decode()}"
        return payload

    def decrypt(self, enc_data):
        """Handle key versioning during decryption"""
        try:
            key_ver, data = enc_data.split(':', 1)
            key_ver = int(key_ver)
            
            # Derive the historical key if needed
            if key_ver != self.key_version:
                dynamic_seed = f"{self.master_key.hex()}{int(time.time()/3600) - (self.key_version - key_ver)}"
                key = hashlib.sha256(dynamic_seed.encode()).digest()
            else:
                key = self.current_key

            data = base64.b64decode(data)
            iv, encrypted = data[:16], data[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(encrypted), AES.block_size).decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
