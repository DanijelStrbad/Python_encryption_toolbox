# pip install pycryptodomex

from os.path import exists
from zipfile import ZipFile

from Cryptodome.Hash import SHA256
from Cryptodome.Hash import SHA512
from Cryptodome.Hash import SHA3_256
from Cryptodome.Hash import SHA3_512

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Cipher import DES3

from Cryptodome.Random import random
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Util.Padding import pad
from Cryptodome.Util.Padding import unpad


def printChoices0() -> None:
    print("")
    print("")
    print("\tWhat do You want?")
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
    print("\t(1) Hash a file\t\t\t\t\t\t -> Q(m) -> hash.txt")
    print("\t(2) Verify hash of a file\t\t\t -> Q1(m) == Q2(m) ?")
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
    print("\t(3) Make AES / DES key\t\t\t\t -> k - key.txt")
    print("\t(4) Symmetrically EnCrypt a file\t -> E(m, k)")
    print("\t(5) Symmetrically DeCrypt a file\t -> D(m, k)")
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
    print("\t(6) Make RSA keys\t\t\t\t\t -> (Pk, Sk) -> pk.pem & sk.pem")
    print("\t(7) Asymmetrically EnCrypt a file\t -> E(m, Pk)")
    print("\t(8) Asymmetrically DeCrypt a file\t -> D(m, Sk)")
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
    print("\t(9)  Pack digital envelope\t\t\t -> digital_envelope = { E(m, k); E(k, pkb) } -> de.zip = { *.c + key.txt.c }")
    print("\t(10) UnPack digital envelope\t\t -> de.zip = { *.c + key.txt.c }")
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
    print("\t(11) Sign a file\t\t\t\t\t -> digital_signature = { m; E[Q(m), ska] } -> ds.zip = { file.xyz + sig.s }")
    print("\t(12) Verify signature of a file\t\t -> ds.zip = { file.xyz + sig.s }")
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
    print("\t(q) Terminate program")
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")

def printChoices1() -> None:
    print("(1) - SHA2-256")
    print("(2) - SHA2-512")
    print("(3) - SHA3-256")
    print("(4) - SHA3-512")

def getHash(fileName: str):
    printChoices1()
    userInput = input("Your choice: ")
    choice = int(userInput)

    if choice < 1 or choice > 4:
        print("Wrong input")
        return None

    file1 = open(fileName, "rb")
    fileIn1 = file1.read()
    file1.close()

    if choice == 1:
        hash1 = SHA256.new()
        hash1.update(fileIn1)
    elif choice == 2:
        hash1 = SHA512.new()
        hash1.update(fileIn1)
    elif choice == 3:
        hash1 = SHA3_256.new()
        hash1.update(fileIn1)
    else:
        hash1 = SHA3_512.new()
        hash1.update(fileIn1)

    return hash1

def hashFile(fileName: str) -> None:
    printChoices1()
    userInput = input("Your choice: ")
    choice = int(userInput)

    if choice < 1 or choice > 4:
        print("Wrong input")
        return None

    file1 = open(fileName, "rb")
    fileIn1 = file1.read()
    file1.close()

    if choice == 1:
        hash1 = SHA256.new()
        hash1.update(fileIn1)
    elif choice == 2:
        hash1 = SHA512.new()
        hash1.update(fileIn1)
    elif choice == 3:
        hash1 = SHA3_256.new()
        hash1.update(fileIn1)
    else:
        hash1 = SHA3_512.new()
        hash1.update(fileIn1)

    file1 = open("hash.txt", "w")
    file1.write(hash1.hexdigest())
    file1.close()

def verifyHash(fileName: str) -> bool:
    printChoices1()
    userInput = input("Your choice: ")
    choice = int(userInput)

    if choice < 1 or choice > 4:
        print("Wrong input")
        return False

    file1 = open(fileName, "rb")
    fileIn1 = file1.read()
    file1.close()

    if choice == 1:
        hash1 = SHA256.new()
        hash1.update(fileIn1)
    elif choice == 2:
        hash1 = SHA512.new()
        hash1.update(fileIn1)
    elif choice == 3:
        hash1 = SHA3_256.new()
        hash1.update(fileIn1)
    else:
        hash1 = SHA3_512.new()
        hash1.update(fileIn1)

    hash1 = hash1.hexdigest()

    file1 = open("hash.txt", "r")
    hash2 = file1.read()
    file1.close()

    if hash1 == hash2:
        print("OK - hashes are equal")
        return True
    else:
        print("WARNING - hashes are NOT equal")
        return False

def makeSimKey() -> None:
    userInput = input("(1) - 128, (2) - 256, (3) - 56: ")
    choice = int(userInput)
    key = ""

    if choice > 3 or choice < 1:
        print("Wrong input")
        return None

    if choice == 1:
        n = 16
    elif choice == 2:
        n = 32
    else:
        n = 24

    for i in range(n):
        int1 = random.randint(33, 126)
        key = key + chr(int1)

    file1 = open("k.txt", "w")
    file1.write(key)
    file1.close()

def symCrypt(fileName: str) -> None:
    userInput = input("(1) - AES 128, (2) - AES 256, (3) - 3DES: ")
    choice = int(userInput)

    if choice > 3 or choice < 1:
        print("Wrong input")
        return None

    userInput = input("(1) - ECB, (2) - CBC: ")
    choice2 = int(userInput)

    if choice2 > 2 or choice2 < 1:
        print("Wrong input")
        return None

    mFile = open(fileName, "rb")
    msg = mFile.read()
    mFile.close()

    fileKey = open("k.txt", "rb")
    key = fileKey.read()
    fileKey.close()

    if choice == 1 or choice == 2:
        if choice2 == 1:
            cipher = AES.new(key, AES.MODE_ECB)
        else:
            cipher = AES.new(key, AES.MODE_CBC)

            iv = cipher.iv
            fileIv = open("iv.txt", "wb")
            fileIv.write(iv)
            fileIv.close()

        ciphertext = cipher.encrypt(pad(msg, 16))

    else:
        if choice2 == 1:
            cipher = DES3.new(key, DES3.MODE_ECB)
        else:
            cipher = DES3.new(key, DES3.MODE_CBC)

            iv = cipher.iv
            fileIv = open("iv.txt", "wb")
            fileIv.write(iv)
            fileIv.close()

        ciphertext = cipher.encrypt(pad(msg, 8))

    fileCipher = open(fileName + ".c", "wb")
    fileCipher.write(ciphertext)
    fileCipher.close()

def symDeCrypt(fileName: str) -> None:
    userInput = input("(1) - AES 128, (2) - AES 256, (3) - 3DES: ")
    choice = int(userInput)

    if choice > 3 or choice < 1:
        print("Wrong input")
        return None

    userInput = input("(1) - ECB, (2) - CBC: ")
    choice2 = int(userInput)

    if choice2 > 2 or choice2 < 1:
        print("Wrong input")
        return None

    cFile = open(fileName, "rb")
    cip = cFile.read()
    cFile.close()

    fileKey = open("k.txt", "rb")
    key = fileKey.read()
    fileKey.close()

    if choice == 1 or choice == 2:
        if choice2 == 1:
            cipher = AES.new(key, AES.MODE_ECB)
        else:
            ivFile = open("iv.txt", "rb")
            iv = ivFile.read()
            ivFile.close()
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)

        msg = unpad(cipher.decrypt(cip), 16)

    else:
        if choice2 == 1:
            cipher = DES3.new(key, DES3.MODE_ECB)
        else:
            ivFile = open("iv.txt", "rb")
            iv = ivFile.read()
            ivFile.close()
            cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)

        msg = unpad(cipher.decrypt(cip), 8)

    fileMsg = open(fileName[0:len(fileName) - 2], "wb")
    fileMsg.write(msg)
    fileMsg.close()

def makeRsaKeys() -> None:
    userInput = input("1024, 2048, 4096: ")
    choice = int(userInput)
    if not (choice == 1024 or choice == 2048 or choice == 4096):
        print("Wrong input")
        return None

    if choice >= 2048:
        print("Please wait . . .")

    key = RSA.generate(choice)
    skFile = open('sk.pem', 'wb')
    skFile.write(key.export_key('PEM'))
    skFile.close()

    pkFile = open('pk.pem', 'wb')
    pkFile.write(key.publickey().exportKey())
    pkFile.close()

def asymCrypt(fileName: str) -> None:
    userInput = input("(1) - pk, (2) - sk: ")
    choice = int(userInput)

    if choice < 1 or choice > 2:
        print("Wrong input")
        return None

    if choice == 1:
        pkFile = open('pk.pem', 'r')
    else:
        pkFile = open('sk.pem', 'r')

    # pkFile = open('pk.pem', 'r')
    pk = RSA.import_key(pkFile.read())
    pkFile.close()

    mFile = open(fileName, "rb")
    msg = mFile.read()
    mFile.close()

    cipher_rsa = PKCS1_OAEP.new(pk)
    cip = cipher_rsa.encrypt(msg)

    fileCipher = open(fileName + ".c", "wb")
    fileCipher.write(cip)
    fileCipher.close()

def asymDeCrypt(fileName: str) -> None:
    userInput = input("(1) - sk, (2) - pk: ")
    choice = int(userInput)

    if choice < 1 or choice > 2:
        print("Wrong input")
        return None

    if choice == 1:
        skFile = open('sk.pem', 'r')
    else:
        skFile = open('pk.pem', 'r')

    # skFile = open('sk.pem', 'r')
    sk = RSA.import_key(skFile.read())
    skFile.close()

    mFile = open(fileName, "rb")
    cip = mFile.read()
    mFile.close()

    cipher_rsa = PKCS1_OAEP.new(sk)
    msg = cipher_rsa.decrypt(cip)

    fileMsg = open(fileName[0:len(fileName) - 2], "wb")
    fileMsg.write(msg)
    fileMsg.close()


def main():
    print("\t\t## Cryptography software ##")

    while 1 == 1:
        printChoices0()

        userInput = input("Your choice: ")
        try:
            choice = int(userInput)
        except ValueError:
            print("Program terminated")
            return None

        if choice < 1 or choice > 12:
            print("Wrong input")
            return None

        print("")

        if choice == 1:
            # SHA2/3
            userInput = input("File: ")
            hashFile(userInput)
            print("Done")

        elif choice == 2:
            # Verify hash of a file
            userInput = input("File: ")
            verifyHash(userInput)

        elif choice == 3:
            # generate key
            makeSimKey()
            print("Done")

        elif choice == 4:
            # Symmetrically EnCrypt a file
            userInput = input("File: ")
            symCrypt(userInput)
            print("Done")

        elif choice == 5:
            # Symmetrically DeCrypt a file
            userInput = input("File: ")
            symDeCrypt(userInput)
            print("Done")

        elif choice == 6:
            # Make RSA keys
            makeRsaKeys()
            print("Done")

        elif choice == 7:
            # Asymmetrically EnCrypt a file
            userInput = input("File: ")
            asymCrypt(userInput)
            print("Done")

        elif choice == 8:
            # Asymmetrically DeCrypt a file
            userInput = input("File: ")
            asymDeCrypt(userInput)
            print("Done")

        elif choice == 9:
            # Pack digital envelope

            fileName = input("File: ")
            symCrypt(fileName)
            asymCrypt("k.txt")

            fileName = fileName + ".c"
            zipEnvelope = ZipFile('de.zip', 'w')
            zipEnvelope.write(fileName)
            zipEnvelope.write("k.txt.c")
            if exists("iv.txt"):
                zipEnvelope.write("iv.txt")
            zipEnvelope.close()

            print("Done")

        elif choice == 10:
            # UnPack digital envelope

            zipEnvelope = ZipFile('de.zip', 'r')
            zipEnvelope.extractall()
            zipEnvelope.close()

            fileName = input("File: ")
            symDeCrypt(fileName)
            asymDeCrypt("k.txt.c")

            print("Done")

        elif choice == 11:
            # Sign a file

            fileName = input("File: ")
            hash1 = getHash(fileName)

            skFile = open('sk.pem', 'r')
            sk = RSA.import_key(skFile.read())
            skFile.close()

            signature = pkcs1_15.new(sk).sign(hash1)

            sigFile = open("sig.s", "wb")
            sigFile.write(signature)
            sigFile.close()

            zipEnvelope = ZipFile('ds.zip', 'w')
            zipEnvelope.write(fileName)
            zipEnvelope.write("sig.s")
            zipEnvelope.close()

            print("Done")

        elif choice == 12:
            # Verify signature of a file

            zipEnvelope = ZipFile('ds.zip', 'r')
            zipEnvelope.extractall()
            zipEnvelope.close()

            fileName = input("File: ")
            hash1 = getHash(fileName)

            pkFile = open('pk.pem', 'r')
            pk = RSA.import_key(pkFile.read())
            pkFile.close()

            sigFile = open("sig.s", "rb")
            signature = sigFile.read()
            sigFile.close()

            try:
                pkcs1_15.new(pk).verify(hash1, signature)
                print("Signature is VALID")
            except (ValueError, TypeError):
                print("WARNING - Signature is NOT valid")

            print("Done")


if __name__ == '__main__':
    main()

