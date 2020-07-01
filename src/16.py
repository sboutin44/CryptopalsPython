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
from block_ciphers import AES128_BLOCKSIZE


def f1(input, key, iv):
    """ Cipher a user input with prepended and appended strings.

     The characters ';' and '=' are removed from the user input so that
     admin=true cannot be set by the user.
     """

    input = bytearray(input)

    # # Quote out ; and = from the input
    while ord(';') in input or ord('=') in input:
        i = input.find(ord(';'))
        if i != -1: input.pop(i)
        i = input.find(ord('='))
        if i != -1: input.pop(i)

    input = bytearray("comment1=cooking%20MCs;userdata=", "ASCII") + input
    input += bytearray(";comment2=%20like%20a%20pound%20of%20bacon", "ASCII")

    padded_plaintext = PKCS7_doPadding(input)
    ciphertext = AES_CBC_encrypt(padded_plaintext, key, iv)

    return ciphertext


def isAdmin(ciphertext, key, iv):
    """ Returns True or False if admin=true is in ciphertext. """

    plaintext = AES_CBC_decrypt(ciphertext, key, iv)

    print("\nDecrypted string:")
    print(bytes(plaintext))

    pos = plaintext.find(b';admin=true;')
    if pos == -1:
        return False
    else:
        return True


def xor(l1, l2):
    assert (len(l1) == len(l2))
    L3 = bytes([l1[i] ^ l2[i] for i in range(len(l1))])
    return L3

def challenge_16():
    """ CBC bitflipping attacks

    To break the AES-CBC, I encrypt a dummy string over a few AES128 blocks:
            block 0             block 1         block 2
        aaaaaaaaaaaaaaaa | aaaaaaaaaaaaaaaa | aaaaaaaaaaaaaaaa

    Which is in hex notation:
        61 61 61 ...  61 | 61 61 61 ...  61  | 61 61 61 ... 61

    Once encrypted (random values):
            ciphertext_0                    ciphertext_1                    ciphertext_2
    1809D7BC1F63E3F5ACB460B6DAE4E891 EEBE6389AC509D5A5EC76B91D145965C 96332E27F13F24866CB1C53A6A5972C7

    We will modify the ciphertext: each bit modifed in the encrypted ciphertext_1 will be seen in the decrypted block 2,
    for instance if I modify EE by FE, the decryped block 2 will be:
    62 61 61 ... 61

    Thus, to replace characters the block 3 of plaintext, we have to 'zero' these characters using the previous
    ciphertext block:
        ciphertext_1 = ciphertext_1 xor '61 61 61 ... 61'
    Then we insert the string we want (padded to 16-bytes):
        ciphertext_1 = ciphertext_1 xor ';admin=true;____'
    """

    key = get_random_bytes(16)
    iv = copy(key)

    plaintext_block = b'aaaaaaaaaaaaaaaa'  # 16 bytes
    plaintext = 3*plaintext_block

    ciphertext = f1(plaintext, key, iv)

    # attack
    adminString = b';admin=true;0000'  # 16-bytes block
    temp = xor(plaintext_block, adminString)
    start = 3 * AES128_BLOCKSIZE
    stop = start + AES128_BLOCKSIZE
    ciphertext[start:stop] = xor(ciphertext[start:stop], temp)

    print("\nisAdmin: " , isAdmin(ciphertext, key, iv))

if __name__ == "__main__":
    challenge_16()
