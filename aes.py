import hashlib
from base64 import b64encode, b64decode
import os

from Crypto.Cipher import AES

# AES code derived from code by Pablo T. Campos
# https://medium.com/quick-code/aes-implementation-in-python-a82f582f51c2

class AESHandler:
    def __init__(self, k):
        self.bs = AES.block_size
        self.k = hashlib.sha256(k.encode()).digest()

    def encrypt(self, tx):
        tx = self.__pad(tx)
        r = os.urandom(self.bs)
        c = AES.new(self.k, AES.MODE_CBC, r)
        return b64encode(r + c.encrypt(tx.encode())).decode("utf-8")

    def decrypt(self, rx):
        rx = b64decode(rx)
        r = rx[:self.bs]
        c = AES.new(self.k, AES.MODE_CBC, r)
        return self.__unpad(c.decrypt(rx[self.bs:])).decode("utf-8")

    def __pad(self, tx):
        n = self.bs - len(tx) % self.bs
        return tx + n * chr(n)

    @staticmethod
    def __unpad(rx):
        return rx[:-ord(rx[len(rx)-1:])]
