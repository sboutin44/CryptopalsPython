# // Copyright © 2020 Sebastien BOUTIN
# //
# // Permission is hereby granted, free of charge, to any person obtaining a copy
# // of this software and associated documentation files (the "Software"), to
# // deal in the Software without restriction, including without limitation the
# // rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# // sell copies of the Software, and to permit persons to whom the Software is
# // furnished to do so, subject to the following conditions:
# //
# // The above copyright notice and this permission notice shall be included in
# // all copies or substantial portions of the Software.
# //
# // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# // IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# // FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# // AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# // LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# // FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# // IN THE SOFTWARE.
# //
# // Except as contained in this notice, the name(s) of the above copyright
# // holders shall not be used in advertising or otherwise to promote the sale,
# // use or other dealings in this Software without prior written authorization.

from Crypto.Random import get_random_bytes
from copy import copy

# My Cryptopals functions
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

