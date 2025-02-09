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

from Crypto.Cipher import AES
from base64 import *

# My Cryptopals functions
from block_ciphers import AES128_BLOCKSIZE

def bytes_to_int(b,order):
    result = 0

    if order == 'little':
        for i in range(len(b)-1,0,-1):
            result = result * 256 + int(b[i])
    else:
        for i in range(0,len(b)):
            result = result * 256 + int(b[i])
    return result

def int_to_bytes(v, l):
    r = []
    for i in range(0, l):
        r.append(v >> (i * 8) & 0xff)
    r.reverse()
    return r

def increment_block(block, l):
    """ Increment a block over l bytes.
        :param block: 00 00 00 00 00 00 00 01
        :return: 00 00 00 00 00 00 00 02    """
    b = bytes_to_int(block)
    b += 1
    return int_to_bytes(b,l)

def AES_CTR_enc(key,nounce, plain):
    """
    :param key: 16-bytes bytes
    :param nounce: int
    :param plain: any string
    :return: encrypted plain.
    """

    assert(type(plain) == bytearray)
    blocksize = AES128_BLOCKSIZE
    l = len(plain)

    # Generates the keysteam. Nounce is on 7 bytes, counter on 9.
    AES_cipher = AES.new(bytes(key,"ASCII"), AES.MODE_ECB)
    block = bytearray(16)
    keysteam = bytearray([])
    nounce_as_block = int_to_bytes(nounce,7)
    nb = int(l / blocksize) + 1
    for counter in range (nb):
        block[0:9] = int_to_bytes(counter,9)
        block[9:16] = nounce_as_block

        # AES block encrpytion
        block = bytearray(AES_cipher.encrypt(bytes(block)))
        keysteam += block

    # Input encryption
    ciphertext = bytearray(l)
    for i in range(l):
        ciphertext[i] += plain[i] ^ keysteam[i]

    return ciphertext

def AES_CTR_dec(key,nounce,cipher):
    return AES_CTR_enc(key, nounce, cipher)

def challenge_18():
    ciphertext = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    c = bytearray(b64decode(bytes(ciphertext,"ASCII")))
    key = 'YELLOW SUBMARINE'
    nounce = 0

    plain_barray = AES_CTR_dec(key,nounce,c)
    plain = str(plain_barray,"ASCII")
    print(plain)

if __name__ == "__main__":
    challenge_18()