import unittest
from functions import checkPrime, primeGen, modularMultiplicativeInverse, gcdExtended, keyGen, encrypt, combineDecrypt, partialDecrypt
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

class TestModularMultiplicativeInverse(unittest.TestCase):
    def test_inverse(self): 
        test_a = [1236, 4215, 5125, 7376, 90539, 925010]
        test_b = [5904, 6042, 41923, 31892, 401293, 8410381]

        for pair in zip(test_a, test_b):
            a = pair[0]
            b = pair[1]
            
            
            if gcdExtended(a, b)[0] == 1:
                inverse_of_a = modularMultiplicativeInverse(a, b)
                self.assertEqual(inverse_of_a, pow(a, -1, b))
                self.assertEqual((inverse_of_a * a) % b, 1, [a, b])
                

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
        test_M = 807

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

if __name__ == '__main__':
    unittest.main()