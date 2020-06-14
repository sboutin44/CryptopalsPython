from Crypto.Random import get_random_bytes
from copy import copy

# My functions
from block_ciphers import PKCS7_doPadding
from block_ciphers import AES_CBC_encrypt
from block_ciphers import AES_CBC_decrypt
from block_ciphers import printHEX

def f1(input, key,iv):
    """ Cipher a user input with prepended and appended strings.

     The characters ';' and '=' are removed from the user input so that
     admin=true cannot be set by the user.
     """

    input = bytearray(input)

    # # Quote out ; and = from the input
    while ord(';') in input or ord('=') in input:
        i = input.find(ord(';'))
        if i!=-1: input.pop(i)
        i = input.find(ord('='))
        if i!=-1: input.pop(i)

    input = bytearray("comment1=cooking%20MCs;userdata=","ASCII") + input
    input += bytearray(";comment2=%20like%20a%20pound%20of%20bacon","ASCII")

    #TODO: remove
    print(input)

    padded_plaintext = PKCS7_doPadding(input)
    ciphertext = AES_CBC_encrypt(padded_plaintext,key,iv)

    return bytes(ciphertext)
    # return ciphertext

def f2(ciphertext, key,iv):
    """ Returns True or False if admin=true is in ciphertext. """

    plaintext = AES_CBC_decrypt(ciphertext,key,iv)

    pos = plaintext.find(b';admin=true;')

    if pos == -1:
        return False
    else:
        return True

if __name__ == "__main__":
    key = get_random_bytes(16)
    iv = copy(key)

    ciphertext = f1(b"admin=true", key, iv)
    print(ciphertext)
    deciphered  = f2(ciphertext, key, iv)
    print(deciphered)


    # printHEX(PKCS7_doPadding(b'coucou'))

