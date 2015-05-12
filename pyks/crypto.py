# -*- coding: utf-8 -*-
"""
Facade for some cryptographic functions done by 'cryptography' or
some other libraries
"""

#---
#--- Python
import os

#---
#--- https://pypi.python.org/pypi/cryptography/
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

#---
class CipherContext(object) :
    """
    Something to derive key and IV from.
    Currently AES-specific, but this might be generalized in future
    """
    def __init__(self) :
        if 1 :
            self.key = os.urandom(32)
            self.iv = os.urandom(16)
        else :
            self.key = b'\x1b\xa2\x17\xfe\x1e&\xd1l-\x9c\xf4$$\xd0\x9c\xf9\x1etA\xd0\xb7:\xe2&\xf6\xb9\x17w\xc76\xb2w'
            self.iv = b'\xae\xd4\x86\xe8\xa4M\xb7m\xa7\x06\x94\xfdW\xb9\x9eT'

    def CreateEncrypter(self):
        """
        @param context: Something to derive key and IV from
        @type  context: L{CipherContext}
        """
        cipher = self._createCipher()
        encryptor = cipher.encryptor()
        return encryptor


    def CreateDecrypter(self):
        """
        @param context: Something to derive key and IV from
        @type  context: L{CipherContext}
        """
        cipher = self._createCipher()
        decryptor = cipher.decryptor()
        return decryptor

    def _createCipher(self):
        """
        @param context: Something to derive key and IV from
        @type  context: L{CipherContext}
        """
        backend = default_backend()
        key = self.key
        iv = self.iv
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = backend)
        return cipher


def aes_example() :
    context = CipherContext()
    encryptor = context.CreateEncrypter()

    plainText = b"a secret message"
    print plainText
    cipherText = encryptor.update(plainText) + encryptor.finalize()
    # ':\xd1\xea\x82\xd2!\xe0,v\x10\xb2\x11\xec\xe7f>'
    print cipherText

    decryptor = context.CreateDecrypter()
    plainText2 = decryptor.update(cipherText) + decryptor.finalize()
    #'a secret message'
    print plainText2
    return
