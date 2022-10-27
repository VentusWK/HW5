import socket
from Crypto.Hash import HMAC, SHA256


try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print ("Socket successfully created")
except socket.error as err:
    print ("socket creation failed with error %s" %(err))

s.bind(('', port))        
print ("socket binded to %s" %(port))

while(menuContinue != 0):
    print("1. Generate HMAC for message m and send it to Bob")
    print("2. Sign a message m and send it to Bob")
    print("3. Calculate average generation time of HMAC")
    print("4. Calculate average generation time of signature")
    print("0. Exit")
    try:
        menuContinue = int(input("Type the number for the action you want to do: "))
    except ValueError:
        print("Not an integer. Try again.")
    if(menuContinue == 1):
        aes.decryptAES()
    elif(menuContinue == 0):
        quit()
    else:
        print("Invalid input. Try again.")