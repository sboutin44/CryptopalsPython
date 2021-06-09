import unittest
import src.c1 as c1


class TestBase64(unittest.TestCase):
    def setUp(self):
        self.plaintexts = [
            "Man",
            "Ma",
            "M",
            "any carnal pleasure.",
            "any carnal pleasure",
            "any carnal pleasur",
            "any carnal pleasu",
            "any carnal pleas",
            "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure."
        ]

        self.encoded = [
            "TWFu",
            "TWE=",
            "TQ==",
            "YW55IGNhcm5hbCBwbGVhc3VyZS4=",
            "YW55IGNhcm5hbCBwbGVhc3VyZQ==",
            "YW55IGNhcm5hbCBwbGVhc3Vy",
            "YW55IGNhcm5hbCBwbGVhc3U=",
            "YW55IGNhcm5hbCBwbGVhcw==",
            "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4="
        ]

    def tearDown(self):
        pass

    def test_encode(self):
        for i in range(len(self.plaintexts)):
            TestBase64.assertEqual(self, c1.Base64.encode(self.plaintexts[i]), self.encoded[i])


    def test_decode(self):
        for i in range(len(self.plaintexts)):
            TestBase64.assertEqual(self, c1.Base64.decode(self.encoded[i]), self.plaintexts[i])


if __name__ == "__main__":
    unittest.main()
