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
    # print("[f2]: deciphered: ", deciphered)
    return PKCS7_validate(deciphered)

def attack_block(block0 , block1, padding_length):
    cipher = block0 + block1
    cipher_original = copy(cipher)
    plaintext = []

    original_padding = padding_length
    new_padding = padding_length
    block_count = int(len(cipher)/ AES128_BLOCKSIZE)

    # for block_nb in range(block_count-1,-1,-1):
    block_nb = block_count - 1
    offset = block_nb * AES128_BLOCKSIZE
    current_block_len = AES128_BLOCKSIZE - padding_length

    while current_block_len > 0:
        # Increase the padding by 1 in the nth-1 cipher block.
        previous_padding = new_padding
        new_padding = new_padding + 1

        # Insert this new padding in the cipher
        for i in range(previous_padding):
            cipher[offset - i - 1] ^= previous_padding ^ new_padding

        # Send it
        f2(cipher, iv)

        # Find the character
        target_byte_pos = offset - 1 - previous_padding
        for i in range (256):
            cipher[target_byte_pos] = i
            # Check when the cipher byte value that validates the new padding"
            if f2(cipher,iv) == True:
                current_block_len -= 1
                if block_nb > 0:
                    plain_byte = i ^ new_padding ^ cipher_original[target_byte_pos]
                # else:
                    # plain_byte = i ^ new_padding ^ iv[target_byte_pos]
                print(plain_byte)
                plaintext.append(plain_byte)
                break

    plaintext.reverse()
    print("Last block: ", bytes(plaintext))


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
    b1 = b'bbbbbbbbbbbbbbbb'
    b2 = b'lkjihgfedcba'

    input = b0 + b1 + b2

    cipher,iv = f1(input)
    cipher_original = copy(cipher)

    # =========================== attack ===========================

    # =========================== Get the padding length ===========================
    #
    # by changing, from "left to right", the content of the block containing the padding,
    # as soon as we modify one of the padding bytes the oracle will say the padding is wrong.
    start = 0
    i = 0
    block_count = int(len(cipher)/ AES128_BLOCKSIZE)
    l = len(cipher)
    plaintext = []

    while (f2(cipher, iv) == True):
        cipher[start + i] = 0xAA
        i += 1
    padding_length = AES128_BLOCKSIZE - (i%AES128_BLOCKSIZE) + 1

    plaintext_len = len(cipher) - padding_length
    cipher = copy(cipher_original)

    print("Padding byte: 0x%02x\n" % padding_length)
    printHEX(cipher)

    # =========================== Find characters ===========================
    #
    original_padding = padding_length
    new_padding = padding_length

    # for block_nb in range(block_count-1,-1,-1):
    block_nb = block_count - 1
    offset = block_nb * AES128_BLOCKSIZE
    current_block_len = AES128_BLOCKSIZE - padding_length

    while current_block_len > 0:
        # Increase the padding by 1 in the nth-1 cipher block.
        previous_padding = new_padding
        new_padding = new_padding + 1

        # Insert this new padding in the cipher
        for i in range(previous_padding):
            cipher[offset - i - 1] ^= previous_padding ^ new_padding

        # Send it
        f2(cipher, iv)

        # Find the character
        target_byte_pos = offset - 1 - previous_padding
        for i in range (256):
            cipher[target_byte_pos] = i
            # Check when the cipher byte value that validates the new padding"
            if f2(cipher,iv) == True:
                current_block_len -= 1
                if block_nb > 0:
                    plain_byte = i ^ new_padding ^ cipher_original[target_byte_pos]
                else:
                    plain_byte = i ^ new_padding ^ iv[target_byte_pos]
                print(plain_byte)
                plaintext.append(plain_byte)
                break

    plaintext.reverse()
    print("Last block: ", bytes(plaintext))
        # print("Last block: " , plaintext.reverse())

    # Decrypt remaining blocks:


if __name__ == "__main__":
    #challenge_17()

    b0 = b'aaaaaaaaaaaaaaaa'
    b1 = b'bbbbbbbbbbbbbbbb'
    b2 = b'lkjihgfedcba'

    input = b0 + b1 + b2

    cipher,iv = f1(input)
    cipher_original = copy(cipher)

    iv2 = bytearray(iv)
    attack_block(iv2[0:16], cipher[0:16], 0)
    attack_block(cipher[0:16], cipher[16:32], 0)
    attack_block(cipher[16:32],cipher[32:48],4)
