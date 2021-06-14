import random
import math
from decimal import Decimal


def checkPrime(n):
    """
    Miller-Rabin primality test.
    
    A return value of False means n is certainly not prime. A return value of
    True means n is very likely a prime.

    source: https://rosettacode.org/wiki/Miller%E2%80%93Rabin_primality_test#Python
    """

    if n!=int(n):
        return False
    n=int(n)
    #Miller-Rabin test for prime
    if n==0 or n==1 or n==4 or n==6 or n==8 or n==9:
        return False
 
    if n==2 or n==3 or n==5 or n==7:
        return True
    s = 0
    d = n-1
    while d%2==0:
        d>>=1
        s+=1
    assert(2**s * d == n-1)
 
    def trial_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2**i * d, n) == n-1:
                return False
        return True  
 
    for i in range(8):#number of trials 
        a = random.randrange(2, n)
        if trial_composite(a):
            return False
 
    return True  

#Generate random odd integer of N bits
def randPrimeCandidate(N):
    if type(N) is not int: return print("[randPrimeCandidate]: argument must be an integer")
    min = 2 ** (N-1) + 1
    max = 2 ** N - 1
    rand = random.randint(min, max)
    if rand ^ 1 == rand + 1:
        return randPrimeCandidate(N)
    else:
        return rand

#Generate random prime number of N bits
def primeGen(N):
    if type(N) is not int: return print("[primeGen]: argument must be an integer")
    while True:
        cand = randPrimeCandidate(N)
        if checkPrime(cand):
            return cand

#Generate two primes such that prime1 * 2 + 1 = prime2
def doublePrimeGen(N):
    if type(N) is not int: return print("[doublePrimeGen]: argument must be an integer")
    while True:
        pprime = primeGen(N)
        p = pprime * 2 + 1
        if checkPrime(p):
            return pprime, p

#Generate l private keys
def privateKeyGen(l, f):
    arr = []
    for i in range(1, l + 1):
        s = f(i)
        arr.append(s)
    return arr

#Key generation
def keyGen(N, t, l):
    """
    key generating function: 
    argument: (integer) length of key in bits
    returns tuple publicKey, array privateKeys 
    """

    if type(N) is not int: return print("[KeyGen]: argument must be an integer")
    if t > l: return print("[keyGen]: the threshold is larger than the number of users")

    pprime, p = doublePrimeGen(int(N / 2 - 1))
    qprime, q = doublePrimeGen(int(N / 2 - 1))

    """
    127 and 128 bit example primes saved for ease of use
    pprime = 146067167902720484939517455959513366529
    qprime = 147732962320765368752842213312543326209
    p = 292134335805440969879034911919026733059
    q = 295465924641530737505684426625086652419
    """

    #n is a kappa(N)-bit number
    n = p * q
    m = pprime * qprime

    #g is a generator of Z*_{n^2}
    g = n + 1

    minverse = pow(m, -1, n ** 2)
    #minverse = 2492172667049954137031565815359910018386221690091877810591444830389243478938830111968672083565316215145114990253510907584709080327977278869048913324813017
    d = m * (minverse % n)
    assert(d % n == 1)

    #Generate coefficients of polynomial
    def coefficientsGen(t, max):
        arr = []
        for i in range(t):
            rand = random.randint(1, max)
            arr.append(rand)
        return arr

    coefficients = coefficientsGen(t, n * m - 1)
    coefficients[0] = d
    
    #coefficients = [296471268930673905512054365950040139586535550346638877905916191418233863167926972796368308378455241483022971141506541702673532242367572701764535025595866, 32427316371702188076291753355467151274429248783846015695625203068339964049165107082530332882221383560279366185382958866692514523987911953583496511881217, 1745469135175642066487962540270413627923483813263315124657500593026017307531864528301619224506504403598406490258315017469002896178382724251638130769133569, 938634784317705678071340187168755733214143655764454479815425870877049167754737437542142026699398832684879737308785697487931212833322053982605257539059713, 1179676158103509390900935691166704342198746382909516050996291474778133577244902308989141642765732219422448539146580815368787079970080685713883011865378817]

    #Polynomial with random coefficients
    def f(x):
        result = 0
        for i, a in enumerate(coefficients):
            result += a * x ** i
        return result

    privateKeys = privateKeyGen(l, f)
    publicKey = (t, l, g, n)

    return publicKey, privateKeys

def encrypt(M, g, n):
    r = random.randint(2, n ** 2 - 1)
    c = (pow(g, M, n ** 2) * pow(r, n, n ** 2)) % (n ** 2)
    return c

def partialDecrypt(c, delta, privateKey, n):
    ci = pow(c, 2 * delta * privateKey, n ** 2)
    return ci

#S array of users of size at least t, C array of partial decryptions ci
def combineDecrypt(S, C, delta, n):
    if len(S) != len(C):
        return print("[combineDecrypt]: arrays have unequal lengths")

    def lambda0(i):
        denominator = 1
        result = 1
        for j in S:
            if j == i: continue
            denominator *= (i - j)
            result *= (-j)
        result *= int(delta / denominator)
        return result
    
    cprime = 1
    for index, user in enumerate(S):
        cprime *= pow(C[index], 2 * lambda0(user), n ** 2)
    cprime %= (n ** 2)

    Mprime = (int((cprime - 1) / n) * pow(4 * delta ** 2, -1, n ** 2)) % n

    return Mprime

def SecureAdd(ciphertext1, ciphertext2, n):
    return (ciphertext1 * ciphertext2) % (n ** 2)
