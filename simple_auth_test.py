
from datetime import (
    datetime,
    timedelta,
)
from unittest import mock
import unittest

import simple_auth


class SimpleAuthTestCase(unittest.TestCase):

    def test_static_encrypt_decrypt(self):
        data = 'hello@gmail.com'
        key = 'cryptographic key'
        encrypted = simple_auth.encrypt(key, data)
        self.assertNotEqual(data, encrypted)
        decrypted = simple_auth.decrypt(key, encrypted)
        self.assertEqual(data, decrypted)

    def test_instance_encrypt_decrypt(self):
        data = 'hello@gmail.com'
        key = 'cryptographic key'
        sut = simple_auth.SimpleAuth(key, default_duration=timedelta(hours=1))
        encrypted = sut.encrypt(data)
        self.assertNotEqual(data, encrypted)
        decrypted = sut.decrypt(encrypted)
        self.assertEqual(data, decrypted)

    def test_encrypt_different_keys(self):
        data = 'hello@gmail.com'
        key1 = 'cryptographic key1'
        key2 = 'cryptographic key2'
        encrypted1 = simple_auth.encrypt(key1, data)
        encrypted2 = simple_auth.encrypt(key2, data)
        self.assertNotEqual(encrypted1, encrypted2)
        decrypted1 = simple_auth.decrypt(key1, encrypted1)
        decrypted2 = simple_auth.decrypt(key2, encrypted2)
        self.assertEqual(decrypted1, decrypted2)

    def test_decrypt_different_keys(self):
        data = 'hello@gmail.com'
        key1 = 'cryptographic key1'
        key2 = 'cryptographic key2'
        encrypted1 = simple_auth.encrypt(key1, data)
        encrypted2 = simple_auth.encrypt(key2, data)
        with self.assertRaises(simple_auth.DecryptionException):
            simple_auth.decrypt(key1, encrypted2)
        with self.assertRaises(simple_auth.DecryptionException):
            simple_auth.decrypt(key2, encrypted1)

    def test_encrypt_invalid_duration(self):
        data = 'hello@gmail.com'
        key = 'cryptographic key'
        simple_auth.encrypt(key, data, minutes=1)
        with self.assertRaises(simple_auth.EncryptionException):
            simple_auth.encrypt(key, data, minutes=0)
        with self.assertRaises(simple_auth.EncryptionException):
            simple_auth.encrypt(key, data, minutes=-1)

    @mock.patch('simple_auth.datetime')
    def test_decrypt_expired(self, mock_dt):
        mock_dt.utcnow = mock.Mock(return_value=datetime(1901, 12, 21))
        data = 'hello@gmail.com'
        key = 'cryptographic key'
        encrypted = simple_auth.encrypt(key, data, minutes=1)
        with self.assertRaises(simple_auth.DecryptionException):
            simple_auth.decrypt(key, encrypted)


if __name__ == '__main__':
    unittest.main()
