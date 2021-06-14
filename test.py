import unittest
from functions import SecureAdd, checkPrime, primeGen, keyGen, encrypt, combineDecrypt, partialDecrypt
from math import factorial

class TestPrimeGen(unittest.TestCase):
    test_N = 10

    def test_is_prime(self):
        self.assertTrue(checkPrime(primeGen(self.test_N)))

    def test_is_N_bits(self):
        lowerLimit = 2 ** (self.test_N-1)
        upperLimit = 2 ** (self.test_N)

        randPrime = primeGen(self.test_N)

        self.assertGreater(randPrime, lowerLimit)
        self.assertLess(randPrime, upperLimit)

class TestEncryptDecrypt(unittest.TestCase):
    def test_single_user(self):
        test_N = 128
        test_l = 1
        test_t = 1
        test_M = 104

        for index in range(1):
            publicKey, privateKeys = keyGen(test_N, test_t, test_l)
            g = publicKey[2]
            n = publicKey[3]
            delta = factorial(test_l)

            encrypted_M = encrypt(test_M, g, n)
            self.assertNotEqual(test_M, encrypted_M)

            partialDecryptions = []
            users = list(range(test_l))
            for user in users:
                partialDecryption = partialDecrypt(encrypted_M, delta, privateKeys[user], n)
                partialDecryptions.append(partialDecryption)
            
            decrypted_M_0 = combineDecrypt([users[0]], [partialDecryptions[0]], delta, n)
            
            self.assertEqual(test_M, decrypted_M_0, [privateKeys[0], encrypted_M, partialDecryption, decrypted_M_0])
        
    def test_multiple_users(self):
        test_N = 128
        test_l = 6
        test_t = 4
        test_M = 1604

        for index in range(1):
            publicKey, privateKeys = keyGen(test_N, test_t, test_l)
            g = publicKey[2]
            n = publicKey[3]
            delta = factorial(test_l)

            encrypted_M = encrypt(test_M, g, n)
            self.assertNotEqual(test_M, encrypted_M)

            partialDecryptions = []
            users = list(range(1, test_l + 1))
            for index, user in enumerate(users):
                partialDecryption = partialDecrypt(encrypted_M, delta, privateKeys[index], n)
                partialDecryptions.append(partialDecryption)
            decrypted_M = combineDecrypt(users, partialDecryptions, delta, n)            
            self.assertEqual(test_M, decrypted_M, [privateKeys, encrypted_M, partialDecryptions, decrypted_M])

class TestSecureAdd(unittest.TestCase):
    def test_two_messages(self):
        message1 = 6542
        message2 = 100002
        test_M = message1 + message2

        test_N = 128
        test_l = 3
        test_t = 2

        for index in range(1):
            publicKey, privateKeys = keyGen(test_N, test_t, test_l)
            g = publicKey[2]
            n = publicKey[3]
            delta = factorial(test_l)
            encrypted_message1 = encrypt(message1, g, n)
            encrypted_message2 = encrypt(message2, g, n)

            encrypted_M = SecureAdd(encrypted_message1, encrypted_message2, n)
            self.assertNotEqual(test_M, encrypted_M)

            partialDecryptions = []
            users = list(range(1, test_l + 1))
            for index, user in enumerate(users):
                partialDecryption = partialDecrypt(encrypted_M, delta, privateKeys[index], n)
                partialDecryptions.append(partialDecryption)
            decrypted_M = combineDecrypt(users, partialDecryptions, delta, n)            
            self.assertEqual(test_M, decrypted_M, [privateKeys, encrypted_M, partialDecryptions, decrypted_M])

if __name__ == '__main__':
    unittest.main()