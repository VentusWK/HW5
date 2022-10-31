from base64 import b64encode
from ssl import HAS_TLSv1_1
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import time

menuContinue = 1

def hmacGenerate(message):
    secretKey = get_random_bytes(16)
    h = HMAC.new(secretKey, digestmod=SHA256)
    h.update(message.encode())
    print("Hash: %s" %(h.hexdigest()))
    with open("mactext.txt", "w") as mactextFile:
        mactextFile.write("%s\n%s\n%s" %(message, h.hexdigest(), b64encode(secretKey).decode('utf-8')))
    return

def rsaSignature(message):
    privateKey = RSA.import_key(open('AlicePrivateKey.pem').read())
    h = SHA256.new(message.encode())
    sig = PKCS1_v1_5.new(privateKey).sign(h)
    print("Message signed")
    with open("sigtext.txt", "w") as sigtextFile:
        sigtextFile.write("%s\n%s" %(message, b64encode(sig).decode('utf-8')))
    return

def benchmarkHMAC(message):
    secretKey = get_random_bytes(16)
    h = HMAC.new(secretKey, digestmod=SHA256)
    start = time.time()
    for i in range(100):
        h.update(message.encode())
    runtime = time.time() - start
    print("HMAC generation average: ", runtime/100 * 10**3," ms" )
    return

def benchmarkSigGen(message):
    privateKey = RSA.import_key(open('AlicePrivateKey.pem').read())
    h = SHA256.new(message.encode())
    start = time.time()
    for i in range(100):
        PKCS1_v1_5.new(privateKey).sign(h)
    runtime = time.time() - start
    print("Signature generation average: ", runtime/100 * 10**3," ms" )

    publicKey = RSA.import_key(open('AlicePublicKey.pem').read())
    sig = PKCS1_v1_5.new(privateKey).sign(h)
    for i in range(100):
        PKCS1_v1_5.new(publicKey).verify(h, sig)
    runtime = time.time() - start
    print("Signature verification average: ", runtime/100 * 10**3," ms" )
    return

def collisionFinder():
    message1 = get_random_bytes(8)
    message2 = get_random_bytes(8)
    h1 = SHA256.new(message1).hexdigest()[0:1]
    h2 = SHA256.new(message2).hexdigest()[0:1]
    numMessages = 0
    while(h1 != h2 or message1 == message2):
        message2 = get_random_bytes(8)
        h2 = SHA256.new(message2).hexdigest()[0:1]
        numMessages += 1
    print("Message 1: " + str(message1))
    print("Message 2: " + str(message2))
    print("%s messages required to find collision" %(numMessages))
    print("Hash: %s" %(h1))

def averageCollisionMessagesFinder():
    numMessages = 0
    sessionMessageCount = []
    for i in range(20):
        message1 = get_random_bytes(1)
        message2 = get_random_bytes(1)
        h1 = SHA256.new(message1).hexdigest()[0:1]
        h2 = SHA256.new(message2).hexdigest()[0:1]
        while(h1 != h2 or message1 == message2):
            message2 = get_random_bytes(1)
            h2 = SHA256.new(message2).hexdigest()[0:1]
            numMessages += 1
        sessionMessageCount.append(numMessages)
        numMessages = 0
    averageNumMessages = sum(sessionMessageCount) / len(sessionMessageCount)
    print("Average of %s messages required to find collision" %(averageNumMessages))
    return

while(menuContinue != 0):
    print("1. Generate HMAC for message m and send it to Bob")
    print("2. Sign a message m and send it to Bob")
    print("3. Calculate HMAC and digital signature performance")
    print("4. Find collisions in the first 8-bits of SHA-256 and calculate average # of messages to find a collision")
    print("0. Exit")
    try:
        menuContinue = int(input("Type the number for the action you want to do: "))
    except ValueError:
        print("Not an integer. Try again.")
    if(menuContinue == 1):
        message = input("Input the message and hit enter: \n")
        hmacGenerate(message)
        input("Press enter to continue")
    elif(menuContinue == 2):
        message = input("Input the message and hit enter: \n")
        rsaSignature(message)
        input("Press enter to continue")
    elif(menuContinue == 3):
        message = input("Input the message and hit enter: \n")
        benchmarkHMAC(message)
        benchmarkSigGen(message)
        input("Press enter to continue")
    elif(menuContinue == 4):
        collisionFinder()
        averageCollisionMessagesFinder()
        input("Press enter to continue")
    elif(menuContinue == 0):
        quit()
    else:
        print("Invalid input. Try again.")