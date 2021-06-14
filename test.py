import unittest
from functions import checkPrime, primeGen, modularMultiplicativeInverse, gcdExtended, keyGen, encrypt, combineDecrypt, partialDecrypt
from math import comb, factorial

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
            inverse_of_a = modularMultiplicativeInverse(a, b)
            
            if gcdExtended(a, b)[0] == 1:
                self.assertEqual((inverse_of_a * a) % b, 1, [a, b])

class TestEncryptDecrypt(unittest.TestCase):
    def test_single_user(self):
        test_N = 11
        test_l = 1
        test_t = 1
        test_M = 4087

        publicKey, privateKey = keyGen(test_N, test_t, test_l)
        g = publicKey[2]
        n = publicKey[3]
        delta = factorial(test_l)

        encrypted_M = encrypt(test_M, g, n)
        self.assertNotEqual(test_M, encrypted_M)

        print(encrypted_M)
        print(privateKey)

        
        
        partialDecrypted_M = partialDecrypt(encrypted_M, delta, privateKey[0])
        print(partialDecrypted_M)
   
        users = [0]
        partialDecryptions = [partialDecrypted_M]
        decrypted_M = combineDecrypt(users, partialDecryptions, delta, n)
        print(decrypted_M)

        return 0



if __name__ == '__main__':
    unittest.main()