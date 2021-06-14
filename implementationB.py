from entities import user, userFactory, thirdParty

#array of 9 private values
privateValues = [15, 16, 17, 18, 19, 20, 21, 22, 23]

#Generate users
users = userFactory(9, privateValues)

#Generate thirdParty
trusted_thirdParty = thirdParty(256, 3, 9)

#Give user publicKey and privateKey
trusted_thirdParty.giveKeys(users)

#Generate userClusters
userClusters = trusted_thirdParty.clusterUsers(users, 3)
trusted_thirdParty.designateRepresentative(userClusters)

def clusterDecryption(cluster):
    representative = cluster[0]
    non_representatives = [u for u in cluster if not u.get_representative()]

    #Tell all users to encrypt
    for u in cluster:
        u.privateEncrypt()

    #Tell all users to send their privateEncrypt to the representative
    for nr in non_representatives:
        nr.sendCipherText([representative])

    #Distribute the total cipher text to other users in the cluster
    representative.sendTotalCiphertext(non_representatives)   

    #Tell all users to partial decrypt using their private key
    for u in cluster:
        u.privatePartialDecrypt()

    #Tell all users to send their partial decrypted text to the representative
    for u in cluster:
        u.sendPartialDecrypt([representative])

    #Tell the representative to decrypt the final message
    representative.totalDecrypt()
    
    return (representative.get_index(), representative.get_totalDecrypt())

representatives = []
for cluster in userClusters:
    index, message = clusterDecryption(cluster)
    representatives.append([u for u in cluster if u.get_index() == index][0])

for r in representatives:
    r.sendPlaintext(representatives)

for cluster in userClusters:
    r = [u for u in cluster if u in representatives][0]
    non_representatives = [u for u in cluster if not u.get_representative()]
    for nr in non_representatives:
        nr.receiveAndAddPlaintext(r.get_plaintext())
    for u in cluster:
        print(u.get_plaintext())
