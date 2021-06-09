import unittest
import src.c1 as c1


class TestBase64(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_encode(self):
        plaintexts = [
            "Man",
            "Ma",
            "M",
            "any carnal pleasure.",
            "any carnal pleasure",
            "any carnal pleasur",
            "any carnal pleasu",
            "any carnal pleas"
        ]

        encoded = [
            "TWFu",
            "TWE=",
            "TQ==",
            "YW55IGNhcm5hbCBwbGVhc3VyZS4=",
            "YW55IGNhcm5hbCBwbGVhc3VyZQ==",
            "YW55IGNhcm5hbCBwbGVhc3Vy",
            "YW55IGNhcm5hbCBwbGVhc3U=",
            "YW55IGNhcm5hbCBwbGVhcw==",
        ]

        for i in range(len(plaintexts)):
            TestBase64.assertEqual(self, c1.Base64.encode(plaintexts[i]), encoded[i])



if __name__ == "__main__":
    unittest.main()
