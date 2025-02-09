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
from Crypto.Cipher import AES
from copy import copy

global AES128_BLOCKSIZE

AES128_BLOCKSIZE = 16

def PKCS7_doPadding(input):
    len_padding = len(input) / AES128_BLOCKSIZE + AES128_BLOCKSIZE
    padding_value = bytes([AES128_BLOCKSIZE - len(input) % AES128_BLOCKSIZE])
    output = input

    for i in range(int.from_bytes(padding_value,sys.byteorder)):
        output += padding_value
        # output.append(padding_value)

    return output

def PKCS7_removePadding(input):
    len_padding = len(input) / AES128_BLOCKSIZE + AES128_BLOCKSIZE
    padding_value = input[-1] #bytes([AES128_BLOCKSIZE - len(input) % AES128_BLOCKSIZE])
    output = copy(input)
    #for i in range(int.from_bytes(padding_value,"big")):
    for i in range(padding_value):
        del output[-1]

    return output

def AES_CBC_encrypt(plaintext,key,IV):
    assert(len(plaintext) % AES128_BLOCKSIZE == 0)

    # Use the AES ECB to encrypt 128-bit blocks
    cipher = AES.new(bytes(key),AES.MODE_ECB)
    ciphertext = bytearray()

    # Cipher 1st block
    block_to_encrypt = bytearray(AES128_BLOCKSIZE)
    for i in range(AES128_BLOCKSIZE):
         block_to_encrypt[i] = IV[i] ^ plaintext[i]
    encrypted_block = cipher.encrypt(bytes(block_to_encrypt))
    ciphertext += bytearray(encrypted_block)

    # Cipher remaining blocks
    for i in range(AES128_BLOCKSIZE,len(plaintext),AES128_BLOCKSIZE):
        for j in range(AES128_BLOCKSIZE):
            block_to_encrypt[j] = plaintext[i+j] ^ ciphertext[i-AES128_BLOCKSIZE + j ]
        ciphertext += cipher.encrypt(bytes(block_to_encrypt))

    return ciphertext

def AES_CBC_decrypt(ciphertext,key,IV):
    assert(len(ciphertext) % AES128_BLOCKSIZE == 0)

    # Use the AES ECB to encrypt 128-bit blocks
    cipher = AES.new(bytes(key),AES.MODE_ECB)
    plaintext = bytearray()

    block_to_decrypt = bytearray(AES128_BLOCKSIZE)

    # decipher fisrt block
    block_to_decrypt = ciphertext[0:AES128_BLOCKSIZE]
    decrypted_block = cipher.decrypt(bytes(block_to_decrypt))
    decrypted_block = bytearray(decrypted_block)
    for i in range(AES128_BLOCKSIZE):
         decrypted_block[i] = IV[i] ^ decrypted_block[i]

    plaintext += decrypted_block

    # Decrypt remaining blocks
    for i in range(AES128_BLOCKSIZE,len(ciphertext),AES128_BLOCKSIZE):
        block_to_decrypt = ciphertext[i:i+AES128_BLOCKSIZE]
        decrypted_block = cipher.decrypt(bytes(block_to_decrypt))
        decrypted_block = bytearray(decrypted_block)
        for j in range(AES128_BLOCKSIZE):
            decrypted_block[j] = decrypted_block[j] ^ ciphertext[i-AES128_BLOCKSIZE + j ]

        plaintext += decrypted_block

    return plaintext


def PKCS7_validate(input, blocksize):
    padding_value = input[len(input)-1]
    if padding_value > blocksize:
        return False

    for i in range(padding_value):
        if (input[len(input)-1-i] != padding_value):
            return False

    return True

def printRawBytes(string):
    for i in range(len(string)):
        print('%02X ' % ord(string[i]),end ='')

def PKCS7_test():
    s0 = b"ICE ICE BABY"
    s1 = b"ICE ICE BABY\x04\x04\x04\x04"
    s2 = b"ICE ICE BABY\x05\x05\x05\x05"
    s3 = b"ICE ICE BABY\x01\x02\x03\x04"
    padded = PKCS7_doPadding(s0)

    assert(s1 == padded)
    assert(s2 != padded)
    assert(s3 != padded)

def printHEX(array):
    for i in range(len(array)):
        if i%AES128_BLOCKSIZE == 0:
            print(' ', end='')
        print('%02X' % array[i], end='')
    print() #newline

def test_AES_CBC():
    PKCS7_test()

    key = bytearray('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', "ASCII")
    iv = copy(key)
    t= b"YELLOW SUBMARINE"
    plaintext = b"YELLOW SUBMARINE"
    padded_plaintext = PKCS7_doPadding(plaintext)
    ciphertext = AES_CBC_encrypt(padded_plaintext,key,iv)

    printHEX(padded_plaintext)
    print("")
    printHEX (ciphertext)

if __name__ == "__main__":
    key = b'Sixteen byte key'
    iv =  b'Sixteen bytes iv'
    plain = b'on all plaintext blocks processed up to that point. To make each message unique, an'

    padded_plain = PKCS7_doPadding(plain)
    ciphertext = AES_CBC_encrypt(padded_plain,key,iv)
    deciphered = AES_CBC_decrypt(ciphertext,key,iv)

    print(bytes(deciphered))
    printHEX(deciphered)
    deciphered = PKCS7_removePadding(deciphered)
    print(bytes(deciphered))