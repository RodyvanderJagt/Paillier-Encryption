from functions import SecureAdd, keyGen, encrypt, partialDecrypt, combineDecrypt
from math import factorial

class user:
    def __init__(self, index, privateValue):
        self.index = index
        self.privateValue = privateValue

    def set_keys(self, publicKey, privateKey = None):
        self.publicKey = publicKey
        self.privateKey = privateKey

    #Encrypt own privateValue
    def privateEncrypt(self):
        g = self.publicKey[2]
        n = self.publicKey[3]
        self.privateCiphertext = encrypt(self.privateValue, g, n)
        self.totalCiphertext = self.privateCiphertext
    
    #Send encrypted private values (ciphertext) to other users
    def sendCipherText(self, users):
        if self.privateCiphertext is None: return print("Something went wrong: I do not have a privateCiphertext")
        for u in users:
            if (u == self): continue
            u.receiveCiphertext(self.privateCiphertext)

    #receive a ciphertext from another user to add to totalCiphertext
    def receiveCiphertext(self, receivedCiphertext):
        if receivedCiphertext is None: return print("Something went wrong: I did not receive a ciphertext")
        n = self.publicKey[3]
        self.totalCiphertext = SecureAdd(self.totalCiphertext, receivedCiphertext, n)

    #partial decrypt of totalCipherText
    def privatePartialDecrypt(self):
        if self.totalCiphertext is None: return print("Something went wrong: I don't have a totalCiphertext")
        delta = factorial(self.publicKey[1])
        n = self.publicKey[3]
        self.partialDecryptedText = partialDecrypt(self.totalCiphertext, delta, self.privateKey, n)
        self.partialDecryptedMessages = []
        self.partialDecryptedMessages.append([self.index, self.partialDecryptedText])

    #send partial decrypted text to other users
    def sendPartialDecrypt(self, users):
        if self.partialDecryptedText is None: return print("Something went wrong: I do not have a partialDecryptedText")
        for u in users:
            if(u == self): continue
            u.receivePartialDecrypt(self.index, self.partialDecryptedText)

    #receive a partially decrypted message (userIndex, partialDecryptedText)
    def receivePartialDecrypt(self, userIndex, partialDecryptedText):
        if partialDecryptedText is None: return print("Something went wrong: I did not receive a partialDecryptedText")
        self.partialDecryptedMessages.append([userIndex, partialDecryptedText])

    #perform combineDecrypt on all collected partial decrypted messages
    def totalDecrypt(self):
        S = [index for index, message in self.partialDecryptedMessages]
        C = [message for index, message in self.partialDecryptedMessages]
        delta = factorial(self.publicKey[1])
        n = self.publicKey[3]
        self.decryptedMessage = combineDecrypt(S, C, delta, n)

    #Decrypted message
    def get_totalDecrypt(self):
        return self.decryptedMessage

class thirdParty:
    def __init__(self, N, t, l):
        self.N = N
        self.t = t
        self.l = l

    def giveKeys(self, users):
        publicKey, privateKeys = keyGen(self.N, self.t, self.l)
        for index, user in enumerate(users):
            user.set_keys(publicKey, privateKeys[index])

def userFactory(l, privateValues):
    users = []
    for index in range(1, l + 1):
        new_user = user(index, privateValues[index - 1])
        users.append(new_user)
    return users