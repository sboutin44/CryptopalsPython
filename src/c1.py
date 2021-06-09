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

class Base64:
    base64_table = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
                    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
                    '8', '9', '+', '/', '=']

    @staticmethod
    def encode(s):
        q = len(s) // 3
        r = len(s) % 3

        encoded = ""

        for i in range(0,3*q,3):
            e0 = Base64.base64_table[(ord(s[i]) & 0xFC) >> 2]
            e1 = Base64.base64_table[(ord(s[i]) & 0x03) << 4 ^ (ord(s[i + 1]) & 0xF0) >> 4]
            e2 = Base64.base64_table[(ord(s[i + 1]) & 0x0F) << 2 ^ (ord(s[i + 2]) & 0xC0) >> 6]
            e3 = Base64.base64_table[(ord(s[i + 2]) & 0x3F)]

            encoded += e0 + e1 + e2 + e3

        i = 3*q
        if r == 2:
            e0 = Base64.base64_table[(ord(s[i]) & 0xFC) >> 2]
            e1 = Base64.base64_table[(ord(s[i]) & 0x03) << 4 ^ (ord(s[i + 1]) & 0xF0) >> 4]
            e2 = Base64.base64_table[(ord(s[i + 1]) & 0x0F) << 2]
            e3 = '='
            encoded +=  e0 + e1 + e2 + e3

        if r == 1:
            e0 = Base64.base64_table[(ord(s[i]) & 0xFC) >> 2]
            e1 = Base64.base64_table[(ord(s[i]) & 0x03) << 4]
            e2 = Base64.base64_table[64]
            e3 = Base64.base64_table[64]
            encoded += e0 + e1 + e2 + e3

        return encoded

    @staticmethod
    def decode(s):
        q = len(s) // 4
        r = len(s) % 4


        decoded = ""

        e0 = ""
        e1 = ""
        e2 = ""
        i0 = 0
        i1 = 0
        i2 = 0
        i3 = 0

        for i in range(0,4*q,4):

            # Get the index in the base64 table corresponding to the next 4 characters.
            # eg: 'T' gives 19.
            for j in range(len(Base64.base64_table)):
                if Base64.base64_table[j] == s[i]:
                    i0 = j
                if Base64.base64_table[j] == s[i+1]:
                    i1 = j
                if Base64.base64_table[j] == s[i+2]:
                    i2 = j
                if Base64.base64_table[j] == s[i+3]:
                    i3 = j

            tmp0 = (i0 << 2) ^ (i1 & 0x30 ) >> 4
            tmp1 = (i1 & 0x0F) << 4 ^ (i2 & 0x3C) >> 2
            tmp2 = (i2 & 0x03) << 6 ^ (i3 & 0x3F)

            e0 = chr(tmp0)
            e1 = chr(tmp1)
            e2 = chr(tmp2)

            decoded += e0 + e1 + e2

        if s[-2:] == "==":
            decoded = decoded[:-2]
        elif s[-1:] == "=":
            decoded = decoded[:-1]

        return decoded


def challenge_1():

    # Encode
    s0 = "Man"
    s1 = "Ma"
    s2 = "M"
    e0 = Base64.encode(s0)
    e1 = Base64.encode(s1)
    e2 = Base64.encode(s2)
    print(e0)
    print(e1)
    print(e2)

    # Decode
    e00 = "TWFu"
    e01 = "TWE="
    e02 = "TQ=="
    d0 = Base64.decode(e00)
    d1 = Base64.decode(e01)
    d2 = Base64.decode(e02)
    print(d0)
    print(d1)
    print(d2)


if __name__ == "__main__":
    challenge_1()
