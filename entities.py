from functions import SecureAdd, keyGen, encrypt, partialDecrypt, combineDecrypt
from math import factorial
import random

class user:
    def __init__(self, index, privateValue):
        self.index = index
        self.privateValue = privateValue
        self.representative = False
        self.totalPlaintext = 0

    def set_keys(self, publicKey, privateKey = None):
        self.publicKey = publicKey
        self.privateKey = privateKey

    def get_index(self):
        return self.index

    def set_representative(self, bool):
        self.representative = bool

    def get_representative(self):
        return self.representative
    
    def get_plaintext(self):
        return self.totalPlaintext

    #Encrypt own privateValue
    def privateEncrypt(self):
        g = self.publicKey[2]
        n = self.publicKey[3]
        self.privateCiphertext = encrypt(self.privateValue, g, n)
        self.totalCiphertext = self.privateCiphertext

        #print('decrypt %d', self.totalCiphertext)
    
    #Send encrypted private values (ciphertext) to other users
    def sendCipherText(self, users):
        if self.privateCiphertext is None: return print("Something went wrong: I do not have a privateCiphertext")
        #print('sending %d', self.privateCiphertext)
        for u in users:
            if (u == self): continue
            u.receiveAndAddCiphertext(self.privateCiphertext)

    #receive a ciphertext from another user to add to totalCiphertext
    def receiveAndAddCiphertext(self, receivedCiphertext):
        if receivedCiphertext is None: return print("Something went wrong: I did not receive a ciphertext")
        n = self.publicKey[3]
        self.totalCiphertext = SecureAdd(self.totalCiphertext, receivedCiphertext, n)

    #send a totalciphertext
    def sendTotalCiphertext(self, users):
        for u in users:
            if u == self: continue
            u.receiveTotalCiphertext(self.totalCiphertext)
        
    #send plaintext
    def sendPlaintext(self, users):
        for u in users:
            u.receiveAndAddPlaintext(self.decryptedMessage)

    def receiveAndAddPlaintext(self, plaintext):
        self.totalPlaintext += plaintext

    #receive a totalciphertext
    def receiveTotalCiphertext(self, receivedTotalCiphertext):
        self.totalCiphertext = receivedTotalCiphertext

    #partial decrypt of totalCipherText
    def privatePartialDecrypt(self):
        if self.totalCiphertext is None: return print("Something went wrong: I don't have a totalCiphertext" + self.index)
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
    
    def clusterUsers(self, users, clusterSize):
        if len(users) % clusterSize != 0: return print("Cluster size must divide the number of users")
        random.shuffle(users)

        userClusters = []
        for cIndex in range(0, len(users), clusterSize):
            cluster = users[cIndex:cIndex + clusterSize]
            userClusters.append(cluster)
        return userClusters

    def designateRepresentative(self, userClusters):
        for cluster in userClusters:
            cluster[0].set_representative(True)

def userFactory(l, privateValues):
    users = []
    for index in range(1, l + 1):
        new_user = user(index, privateValues[index - 1])
        users.append(new_user)
    return users