from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import time


class aes:
    iv = get_random_bytes(16)  # 128 bit iv
    with open("iv.txt", "w") as file:
        file.write(b64encode(iv).decode('utf-8'))

    def encryptAES():
        key = get_random_bytes(16)  # 128 bit key
        with open("secretKey.txt", "w") as keyFile, open("ctext.txt", "w") as cipherTextFile:
            keyFile.write(b64encode(key).decode('utf-8'))
            cipher = AES.new(key, AES.MODE_CBC, iv=aes.iv)
            message = input("Input the message you want to encrypt: ").encode()
            cipherText = b64encode(cipher.encrypt(pad(message, AES.block_size))).decode('utf-8')
            print("Ciphertext: " + cipherText)
            cipherTextFile.write(cipherText)
        input("Hit enter to continue")
        return

class rsa:

    def encryptRSA():
        try:
            with open("publicKey.txt", "rb") as publicKeyFile, open("ctext.txt", "w") as cipherTextFile:
                key = RSA.import_key(publicKeyFile.read())
                cipher = PKCS1_OAEP.new(key)
                message = input("Input the message you want to encrypt: ").encode()
                cipherText = b64encode(cipher.encrypt(message)).decode('utf-8')
                print("Ciphertext: " + cipherText)
                cipherTextFile.write(cipherText)
        except FileNotFoundError:
            print("Public Key not found. Try again.")
        except ValueError:
            print("Message is too long. Try again.")
        input("Hit enter to continue")
        return

def testAES(bits:int, keyFileName:str, ctextFileName:str, message:bytes):

    key = get_random_bytes(bits // 8)
    with open(keyFileName, "w") as keyFile, open(ctextFileName, "w") as cipherTextFile:
        keyFile.write(b64encode(key).decode('utf-8'))
        start = time.time()
        for i in range(100):
            cipher = AES.new(key, AES.MODE_CBC, iv=aes.iv)
            cipherText = b64encode(cipher.encrypt(pad(message, AES.block_size))).decode('utf-8')
        runtime = time.time() - start
        print("AES-"+ str(bits) +" encryption average: ", runtime/100 * 10**3," ms" )
        cipherTextFile.write(cipherText)
    return

def testRSA(bits:int, publicKeyFileName:str, cipherTextFileName:str, message:bytes):
    try:
        with open(publicKeyFileName, "rb") as publicKeyFile, open(cipherTextFileName, "w") as cipherTextFile:
            key = RSA.import_key(publicKeyFile.read())
            start = time.time()
            for i in range(100):
                cipher = PKCS1_OAEP.new(key)
                cipherText = b64encode(cipher.encrypt(message)).decode('utf-8')
            runtime = time.time() - start
            print("RSA-"+ str(bits) +" encryption average: ", runtime/100 * 10**3," ms" )
            cipherTextFile.write(cipherText)
    except FileNotFoundError:
        print("Public Key not found. Try again.")
    except ValueError:
        print("Message is too long. Try again.")
    return

menuContinue = 1
while(menuContinue != 0):
    print("1. Generate random key and encrypt to ctext file using AES-128")
    print("2. Read from publicKey.txt and encrypt to ctext file using RSA-2048")
    print("3. Calculate average encryption time for AES")
    print("4. Calculate average encryption time for RSA")
    print("0. Exit")
    try:
        menuContinue = int(input("Type the number for the action you want to do: "))
    except ValueError:
        print("Not an integer. Try again.")
    if(menuContinue == 1):
        aes.encryptAES()
    elif(menuContinue == 2):
        rsa.encryptRSA()
    elif(menuContinue == 3):
        message = bytes(input("Input the message you want to encrypt (hit enter for random 7-bit message): ").encode() or get_random_bytes(7))
        testAES(128, "secretKey128.txt", "ctext128.txt", message)
        testAES(192, "secretKey192.txt", "ctext192.txt", message)
        testAES(256, "secretKey256.txt", "ctext256.txt", message)
        input("Hit enter to continue")
    elif(menuContinue == 4):
        message = bytes(input("Input the message you want to encrypt (hit enter for random 7-bit message): ").encode() or get_random_bytes(7))
        testRSA(1024, "publicKey1024.txt", "ctext1024.txt", message)
        testRSA(2048, "publicKey2048.txt", "ctext2048.txt", message)
        testRSA(4096, "publicKey4096.txt", "ctext4096.txt", message)
        input("Hit enter to continue")
    elif(menuContinue == 0):
        quit()
    else:
        print("Invalid input. Try again.")