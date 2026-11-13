import unittest

from tgct526g.crypto import decrypt_bytes, encrypt_bytes


class TestCrypto(unittest.TestCase):
    def test_roundtrip(self):
        payload = b'{"account":"demo","password":"demopass"}'
        blob = encrypt_bytes(payload, "test-password")
        self.assertTrue(blob.startswith(b"TGCTCRY1"))
        self.assertEqual(decrypt_bytes(blob, "test-password"), payload)

    def test_wrong_password(self):
        blob = encrypt_bytes(b"secret", "right")
        with self.assertRaises(Exception):
            decrypt_bytes(blob, "wrong")


if __name__ == "__main__":
    unittest.main()
