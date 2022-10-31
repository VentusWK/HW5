from base64 import b64decode
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

def hmacValidate(message, hash, secretKey):
    h = HMAC.new(secretKey, digestmod=SHA256)
    h.update(message.encode())
    try:
        h.hexverify(hash)
        print("Message is valid. Verification succeeded.")
    except ValueError:
        print("The message or the key is incorrect")

def rsaSignatureVerification(message, sig):
    publicKey = RSA.import_key(open("AlicePublicKey.pem").read())
    h = SHA256.new(message.encode())
    if(PKCS1_v1_5.new(publicKey).verify(h, sig)):
        print("Signature is valid.")
    else:
        print("Signature is invalid.")
    return

menuContinue = 1
while(menuContinue != 0):
    print("1. Validate HMAC from Alice")
    print("2. Verify a signature from Alice")
    print("0. Exit")
    try:
        menuContinue = int(input("Type the number for the action you want to do: "))
    except ValueError:
        print("Not an integer. Try again.")
    if(menuContinue == 1):
        with open("mactext.txt", "r") as mactextFile:
            lines = mactextFile.read().splitlines(False)
            message = lines[0]
            hash = lines[1]
            secretKey = b64decode(lines[2])
        hmacValidate(message, hash, secretKey)
        input("Press enter to continue")
    elif(menuContinue == 2):
        with open("sigtext.txt") as sigtextFile:
            lines = sigtextFile.read().splitlines(False)
            message = lines[0]
            sig = b64decode(lines[1])
        rsaSignatureVerification(message, sig)
        input("Press enter to continue")
    elif(menuContinue == 0):
        quit()
    else:
        print("Invalid input. Try again.")