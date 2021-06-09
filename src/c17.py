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
import sys

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
key = b'1111111111111111'
# key = get_random_bytes(16)

def f1(input):
    """ CBC Encrypt one of the string in the Strings[] list."""

    plaintext = input

    iv = b'0000000000000001'
    # iv = b'\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31'
    # iv = b'1111111111111111'
    # iv =copy(key)

    padded_plaintext = PKCS7_doPadding(plaintext)
    assert(PKCS7_validate(padded_plaintext, AES128_BLOCKSIZE) == True )
    print(padded_plaintext)
    ciphertext = AES_CBC_encrypt(padded_plaintext,key,iv)

    return ciphertext,iv

def f2(ciphertext,iv):
    ciphertext = bytes(ciphertext)
    deciphered = AES_CBC_decrypt(ciphertext,key,iv)
    # print("[f2]: deciphered: ", deciphered)
    return PKCS7_validate(deciphered, AES128_BLOCKSIZE)


def attack(block0 , block1, padding_length, iv):
    '''Recover a block of plaintext from 2 ciphertext blocks of AES128 blocksize.'''

    assert (len(block0) == AES128_BLOCKSIZE and len(block1) == AES128_BLOCKSIZE)
    cipher_l = block0 + block1
    cipher_l_original = copy(cipher_l)
    plaintext = []
    new_padding = padding_length
    remaining_bytes = AES128_BLOCKSIZE - padding_length

    while remaining_bytes > 0:
        # Increase the padding by 1 in the nth-1 cipher_l block.
        previous_padding = new_padding
        new_padding = previous_padding + 1

        # Insert this new padding in the cipher_l
        # for i in range(previous_padding):
        for i in range(new_padding):
            cipher_l[AES128_BLOCKSIZE - i - 1] ^= previous_padding ^ new_padding

        # Find the character
        target_byte_pos = AES128_BLOCKSIZE - new_padding
        # print("target_byte_pos: " , target_byte_pos)
        for i in range (256):
            cipher_l[target_byte_pos] = i

            # Check when the cipher_l byte value that validates the new padding"
            if f2(cipher_l, iv) == True:
                remaining_bytes -= 1
                plain_byte = i ^ new_padding ^ cipher_l_original[target_byte_pos]
                plaintext.append(plain_byte)
                # print("found: " , bytes([plain_byte]))
                break
        # if i == 255:
            # print("character not find")

    plaintext.reverse()
    print("Last block: ", bytes(plaintext))
    print("Last block: ", b64decode(bytes(plaintext)))

    return plaintext


def challenge_17():
    """ The CBC padding oracle

    The key and IV are fixed.
    """

    #TODO: add when the attack is ready
    # Pick the random string:
    n = int(random() * 10)
    assert(n<10)
    plaintext = bytes(Strings[n],"ASCII")

    b0 = b'aaaaaaaaaaaaaaaa'
    b1 = b'bbbbbbbbbbbbbbbb'
    b2 = b'cccccccccccccccc' #b'lkjihgfedcba'
    b3 = b'dddddddddddddddd' #b'lkjihgfedcba'
    b4 = b'eeeeeeeeeeee' #b'lkjihgfedcba'

    # input = b0 + b1 + b2 + b3 + b4
    input = plaintext # for the challenge

    cipher,iv = f1(input) # generate the IV
    cipher_original = copy(cipher)

    # =========================== Get the padding length ===========================
    #
    # by changing, from "left to right", the content of the block containing the padding,
    # as soon as we modify one of the padding bytes the oracle will say the padding is wrong.

    i = 0
    while (f2(cipher, iv) == True):
        pos = len(cipher) - 2*AES128_BLOCKSIZE + i
        cipher[pos] = 0xAA
        i += 1
    padding_length = AES128_BLOCKSIZE - i + 1
    cipher = copy(cipher_original) # Restore the original cipher

    print("Padding byte: 0x%02x\n" % padding_length)
    printHEX(cipher)

    blocks =  len(cipher) / AES128_BLOCKSIZE
    plaintext = []
    iv2 = bytearray(iv)

    # for the challenge
    plaintext.append( attack(iv2[0:16], cipher[0:16], 0, iv2) )
    for i in range(0,len(cipher) - AES128_BLOCKSIZE, AES128_BLOCKSIZE):
        b0 = cipher[ i: i + AES128_BLOCKSIZE]
        b1 = cipher[ i + AES128_BLOCKSIZE : i + 2*AES128_BLOCKSIZE ]
        plaintext.append( attack(b0,b1,0,iv2) )

    # for i in range(1,blocks-2):
    #     b0 = cipher[ i * AES128_BLOCKSIZE: (i+1) * AES128_BLOCKSIZE]
    #     b1 = cipher[ (i+1) * AES128_BLOCKSIZE : (i+2) *AES128_BLOCKSIZE]
    #     plaintext.append( attack(b0,b1,0,iv2) )

    # attack(iv2[0:16], cipher[0:16], 0, iv2)
    # attack(cipher[0:16], cipher[16:32], 0, iv2)
    # attack(cipher[0:16], cipher[16:32], 0, iv2)
    # attack(cipher[16:32],cipher[32:48],padding_length, iv2)

if __name__ == "__main__":
    challenge_17()