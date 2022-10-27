from base64 import b64decode
from curses import keyname
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import time
import glob, os

class aes:
    with open("iv.txt", "r") as file:
        iv = b64decode(file.read())  # 128 bit iv

    def decryptAES():
        try:
            with open("secretKey.txt", "rb") as keyFile, open("ctext.txt", "r") as cipherTextFile:
                key = b64decode(keyFile.read())  # 128 bit key
                ciphertext = cipherTextFile.read()
                cipher = AES.new(key, AES.MODE_CBC, iv=aes.iv)
                plaintext = unpad(cipher.decrypt(b64decode(ciphertext)), AES.block_size).decode()
                print("Ciphertext: " + ciphertext)
                print("Decrypted Plaintext: " + plaintext)
        except FileNotFoundError:
            print("Secret Key file not found. Try again.")
        except ValueError:
            print("Invalid decryption. Did you encrypt using RSA?")
        input("Hit enter to continue")
        return

class rsa:
    key = RSA.generate(2048)
    privateKey = key.export_key()
    publicKey = key.public_key().export_key()
    with open("publicKey.txt", "wb") as file:
        file.write(publicKey)

    def createKeys():
        rsa.key = RSA.generate(2048)
        rsa.privateKey = rsa.key.export_key()
        rsa.publicKey = rsa.key.public_key().export_key()
        with open("publicKey.txt", "wb") as file:
            file.write(rsa.publicKey)
        return

    def decryptRSA():
        cipher = PKCS1_OAEP.new(RSA.import_key(rsa.privateKey))
        try:
            with open("ctext.txt", "r") as file:
                cipherText = file.read()
                plaintext = cipher.decrypt(b64decode(cipherText)).decode()
                print("Ciphertext: " + cipherText)
                print("Decrypted Plaintext: " + plaintext)
        except FileNotFoundError:
            print("Cipher text file not found. Try again.")
        except ValueError:
            print("Incorrect Decryption. Try creating a new key pair before encrypting.")
        input("Hit enter to continue")
        return


class rsaTest:

    def __init__(self, bits:int) -> None:
        self.bits = bits
        self.createKeys(bits)
        pass

    def createKeys(self, bits:int):
        self.key = RSA.generate(bits)
        self.privateKey = self.key.export_key()
        self.publicKey = self.key.public_key().export_key()
        with open("publicKey"+ str(bits) + ".txt", "wb") as file:
            file.write(self.publicKey)
        return

    def decryptRSA(self):
        try:
            with open("ctext"+ str(self.bits) + ".txt", "r") as file:
                cipherText = file.read()
                start = time.time()
                for i in range(100):
                    cipher = PKCS1_OAEP.new(RSA.import_key(self.privateKey))
                    plaintext = cipher.decrypt(b64decode(cipherText)).decode()
                runtime = time.time() - start
                print("RSA-"+ str(self.bits) +" average: ", runtime/100 * 10**3," ms" )
                print("Decrypted Plaintext: " + plaintext)
        except FileNotFoundError:
            print("Cipher text file not found. Try again.")
        return



def testAES(bits:int, keyFileName:str, ctextFileName:str):
    try:
        with open(keyFileName, "rb") as keyFile, open(ctextFileName, "r") as cipherTextFile:
            key = b64decode(keyFile.read())  # 128 bit key
            ciphertext = cipherTextFile.read()
            start = time.time()
            for i in range(100):
                cipher = AES.new(key, AES.MODE_CBC, iv=aes.iv)
                plaintext = unpad(cipher.decrypt(b64decode(ciphertext)), AES.block_size).decode()
            runtime = time.time() - start
            print("AES-"+ str(bits) +" average: ", runtime/100 * 10**3," ms" )
    except FileNotFoundError:
        print("Secret Key file not found. Try again.")
    return

benchmark1024 = rsaTest(1024)
benchmark2048 = rsaTest(2048)
benchmark4096 = rsaTest(4096)
menuContinue = 1
print("Key pair generated.")
while(menuContinue != 0):
    print("1. Read from secretKey.txt and decrypt from ctext file using AES-128")
    print("2. Decrypt from ctext file using RSA-2048")
    print("3. Calculate average decryption time of AES")
    print("4. Calculate average decryption time of RSA")
    print("5. Create a public/private key pair and write the public key to publicKey.txt")
    print("0. Exit")
    try:
        menuContinue = int(input("Type the number for the action you want to do: "))
    except ValueError:
        print("Not an integer. Try again.")
    if(menuContinue == 1):
        aes.decryptAES()
    elif(menuContinue == 2):
        rsa.decryptRSA()
    elif(menuContinue == 3):
        testAES(128, "secretKey128.txt", "ctext128.txt")
        testAES(192, "secretKey192.txt", "ctext192.txt")
        testAES(256, "secretKey256.txt", "ctext256.txt")
        input("Hit enter to continue")
    elif(menuContinue == 4):
        benchmark1024.decryptRSA()
        benchmark2048.decryptRSA()
        benchmark4096.decryptRSA()
        input("Hit enter to continue")
    elif(menuContinue == 5):
        rsa.createKeys()
        benchmark1024.createKeys(1024)
        benchmark2048.createKeys(2048)
        benchmark4096.createKeys(4096)
    elif(menuContinue == 0):
        quit()
    else:
        print("Invalid input. Try again.")