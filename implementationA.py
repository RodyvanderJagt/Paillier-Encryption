from entities import userFactory, thirdParty
from math import factorial

#array of 9 private values
privateValues = [15, 16, 17, 18, 19, 20, 21, 22, 23]

#Generate users
users = userFactory(9, privateValues)

#Generate thirdParty
trusted_thirdParty = thirdParty(256, 5, 9)

#Give user publicKey and privateKey
trusted_thirdParty.giveKeys(users)

#Tell all users to encrypt
for u in users:
    u.privateEncrypt()

#Tell all users to send their privateEncrypt
for u in users:
    u.sendCipherText(users)

#Tell all users to partial decrypt using their private key
for u in users:
    u.privatePartialDecrypt()

#Tell all users to send their partial decrypted text
for u in users:
    u.sendPartialDecrypt(users)

#Tell all users to decrypt the final message
for u in users:
    u.totalDecrypt()

"""
for u in users:
    print(u.get_totalDecrypt())
"""
    
