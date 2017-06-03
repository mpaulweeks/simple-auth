# https://github.com/mpaulweeks/simple-auth

from base64 import (
    urlsafe_b64encode,
    urlsafe_b64decode,
)
from datetime import (
    datetime,
    timedelta,
)


class EncryptionException(Exception):
    pass


class DecryptionException(Exception):
    pass


class SimpleAuth:
    class Crypto:
        # using Vigenere Cipher for now, planning to improve
        # Implementation: https://stackoverflow.com/a/38223403/6461842

        @classmethod
        def encode(cls, key, clear):
            enc = []
            for i in range(len(clear)):
                key_c = key[i % len(key)]
                enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
                enc.append(enc_c)
            return urlsafe_b64encode("".join(enc).encode()).decode()

        @classmethod
        def decode(cls, key, enc):
            dec = []
            enc = urlsafe_b64decode(enc).decode()
            for i in range(len(enc)):
                key_c = key[i % len(key)]
                dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
                dec.append(dec_c)
            return "".join(dec)

    DATE_FORMAT = '%Y%m%d%H%M'
    SEPERATOR = '|'

    def __init__(self, key, default_duration=None):
        self.key = key
        self.default_duration = default_duration or timedelta()

    def encrypt(self, user_id, duration=None):
        time_obj_1 = datetime.utcnow() - timedelta(seconds=1)
        time_obj_2 = time_obj_1 + (duration or self.default_duration)
        if time_obj_2 <= time_obj_1:
            raise EncryptionException
        code = self.SEPERATOR.join([
            user_id,
            time_obj_1.strftime(self.DATE_FORMAT),
            time_obj_2.strftime(self.DATE_FORMAT)
        ])
        return self.Crypto.encode(self.key, code)

    def decrypt(self, encrypted):
        code = self.Crypto.decode(self.key, encrypted)
        try:
            user_id, time_string_1, time_string_2 = code.split(self.SEPERATOR)
            time_obj_1 = datetime.strptime(time_string_1, self.DATE_FORMAT)
            time_obj_2 = datetime.strptime(time_string_2, self.DATE_FORMAT)
            now_obj = datetime.utcnow()
            if time_obj_1 < now_obj and now_obj < time_obj_2:
                return user_id
            else:
                raise Exception
        except Exception:
            raise DecryptionException


def encrypt(key, user_id, minutes=15):
    return SimpleAuth(key).encrypt(user_id, timedelta(minutes=minutes))


def decrypt(key, encrypted):
    return SimpleAuth(key).decrypt(encrypted)
