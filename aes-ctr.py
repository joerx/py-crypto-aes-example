import pyaes
import pbkdf2
import binascii
import os
import secrets
import sys
import argparse
from args import parse_args
from getpass import getpass


def mkkey(password, salt):
    return pbkdf2.PBKDF2(password, salt).read(32)


def iv_to_bytes(iv):
    return iv.to_bytes(32, "little", signed=False)


def iv_from_bytes(iv):
    return int.from_bytes(iv, "little", signed=False)


def decrypt(password, salt, iv, ciphertext):
    key = mkkey(password, salt)
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    decrypted = aes.decrypt(ciphertext)
    return decrypted


def encrypt(password, plaintext):
    salt = os.urandom(16)
    key = mkkey(password, salt)
    iv = secrets.randbits(256)
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    return aes.encrypt(plaintext), iv, salt


def main():
    args = parse_args()
    data = args.input.read()

    password = getpass('Enter password: ')

    if args.op == "enc":
        ciphertext, iv, salt = encrypt(password, data)

        print("salt:", binascii.hexlify(salt), file=sys.stderr)
        print("iv:", binascii.hexlify(iv_to_bytes(iv)), file=sys.stderr)

        args.output.write(salt)            # salt, 16 bytes
        args.output.write(iv_to_bytes(iv)) # iv, 32 bytes
        args.output.write(ciphertext)      # ciphertext, remaining bytes

    elif args.op == "dec":
        salt = data[0:16]          # password salt, first 16 bytes
        iv_bytes = data[16:48]     # iv, next 32 bytes
        ciphertext = data[48:]     # ciphertext, remaining bytes

        print("salt:", binascii.hexlify(salt), file=sys.stderr)
        print("iv:", binascii.hexlify(iv_bytes), file=sys.stderr)
        
        iv = iv_from_bytes(iv_bytes)
        decrypted = decrypt(password, salt, iv, ciphertext)
        args.output.write(decrypted)

    else:
        raise Exception("Unknow operation: {}".format(args.op))


if __name__ == '__main__':
    main()
