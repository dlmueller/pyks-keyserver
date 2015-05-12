# -*- coding: utf-8 -*-
"""
@requires: pycrypto
"""
from Crypto.Cipher import AES

def main() :
    obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    message = "The answer is no"
    ciphertext = obj.encrypt(message)
    ciphertext
    # '\xd6\x83\x8dd!VT\x92\xaa`A\x05\xe0\x9b\x8b\xf1'
    obj2 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    obj2.decrypt(ciphertext)
    # 'The answer is no'
    return

if __name__ == '__main__' :
    main()
