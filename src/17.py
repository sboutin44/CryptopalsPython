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
from random import random
from base64 import *

# My Cryptopals functions
from block_ciphers import PKCS7_doPadding
from block_ciphers import PKCS7_validate
from block_ciphers import AES_CBC_encrypt
from block_ciphers import AES_CBC_decrypt
from block_ciphers import printHEX
from block_ciphers import AES128_BLOCKSIZE

Strings= [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

# Global key reused by the oracle
key = get_random_bytes(16)


def f1(input):
    """ CBC Encrypt one of the string in the Strings[] list."""

    plaintext = input

    iv = copy(key)

    padded_plaintext = PKCS7_doPadding(plaintext)
    print(padded_plaintext)
    ciphertext = AES_CBC_encrypt(padded_plaintext,key,iv)

    return ciphertext,iv

def f2(ciphertext,iv):
    ciphertext = bytes(ciphertext)
    deciphered = AES_CBC_decrypt(ciphertext,key,iv)
    print("[f2]: deciphered: ", deciphered)
    return PKCS7_validate(deciphered)


def challenge_17():
    """ The CBC padding oracle

    The key and IV are fixed.
    """

    #TODO: add when the attack is ready
    # # Pick the random string:
    # n = int(random() * 10)
    # assert(n<10)
    # plaintext = bytes(Strings[n],"ASCII")

    b0 = b'aaaaaaaaaaaaaaaa'
    b1 = b'aaaaaaaaaaaa'
    assert(len(b0) == 16)
    input = b0 + b1

    cipher,iv = f1(input)
    cipher_original = copy(cipher)

    print("\nOriginal ciphertext:")
    printHEX(cipher)
    print()

    # attack ===========================

    # Get the padding length by changing, from "left to right", the content of the block containing the padding,
    # as soon as we modify one of the padding bytes the oracle will say the padding is wrong.
    start = 0
    i = 0

    b0_backup = cipher[start:start+AES128_BLOCKSIZE]
    while (f2(cipher, iv) == True):
        last_byte = cipher[start + i]
        cipher[start + i] = 0xAA
        i += 1
        padding_length = AES128_BLOCKSIZE - i + 1

    #cipher[start:start+AES128_BLOCKSIZE] = b0_backup
    cipher = copy(cipher_original)

    # Restore the first byte of padding
    # cipher[start + i - 1] = last_byte

    print("Padding byte: 0x%02x\n" % padding_length)
    printHEX(cipher)

    # Increase the padding value by 1 and inject it in the cipher.
    new_padding = padding_length+1

    for i in range(padding_length):
        cipher[AES128_BLOCKSIZE - i-1] ^= padding_length ^ new_padding

    print("Ciphertext after new padding insertion:")
    printHEX(cipher)
    f2(cipher, iv)

    target_byte_pos = AES128_BLOCKSIZE - 1 - padding_length
    for i in range (256):
        cipher[target_byte_pos] = i
        # If we found the the cipher byte value that validates the new padding"
        if f2(cipher,iv) == True:
            I2 = i ^ new_padding
            plain_byte = I2 ^ cipher_original[target_byte_pos]
            break

    # plain_byte = almost_plain_byte ^ last_byte
    print("Plain byte: " , plain_byte)

if __name__ == "__main__":
    challenge_17()
