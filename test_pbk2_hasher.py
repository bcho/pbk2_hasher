import unittest

import pbk2_hasher


class TestPBK2Hasher(unittest.TestCase):

    def test_make_and_check_password(self):
        pts = (
            ('foobar', None),
            ('hello-world', 'my-salt'),
            (pbk2_hasher.get_random_string(1024), None),
        )

        for plain_text, salt in pts:
            encoded = pbk2_hasher.make_password(plain_text, salt)
            self.assertTrue(pbk2_hasher.check_password(plain_text, encoded))
            self.assertFalse(pbk2_hasher.check_password(plain_text + 'invalid',
                                                        encoded))

    def test_check_with_another_algorithm(self):
        hasher = pbk2_hasher.PBKDF2PasswordHasher()
        encoded = hasher.encode('foobar', hasher.salt())
        updated = encoded.replace(hasher.algorithm, 'home-made-algorithm')
        self.assertFalse(hasher.verify('foobar', updated))


if __name__ == '__main__':
    unittest.main()
