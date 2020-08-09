from Crypto.Cipher import AES
import binascii
import os
import sys
import pbkdf2
from getpass import getpass
from args import parse_args


def mk_key(password, salt):
    return pbkdf2.PBKDF2(password, salt).read(32)


def encrypt(plaintext, key):
    aes = AES.new(key, AES.MODE_GCM)
    ciphertext, auth_tag = aes.encrypt_and_digest(plaintext)
    return ciphertext, aes.nonce, auth_tag


def decrypt(ciphertext, nonce, auth_tag, key):
    aes = AES.new(key, AES.MODE_GCM, nonce)
    plaintext = aes.decrypt_and_verify(ciphertext, auth_tag)
    return plaintext


def main():
    args = parse_args()

    password = getpass('Enter password: ')

    data = args.input.read()

    if args.op == 'enc':
        salt = os.urandom(16)
        key = mk_key(password, salt)
        cipher_text, nonce, auth_tag = encrypt(data, key)

        print("Nonce:", binascii.hexlify(nonce), file=sys.stderr)
        print("Auth tag:", binascii.hexlify(auth_tag), file=sys.stderr)

        # Format: | salt | nonce | auth_tag | cipher_text ...
        args.output.write(salt)        # 16 bytes
        args.output.write(nonce)       # 16 bytes
        args.output.write(auth_tag)    # 16 bytes
        args.output.write(cipher_text) # remaning bytes

    elif args.op == 'dec':
        salt = data[0:16]           # password salt, first 16 bytes
        nonce = data[16:32]         # iv, next 32 bytes
        auth_tag = data[32:48]      # ciphertext, remaining bytes
        cipher_text = data[48:]     # remaining bytes

        print("Nonce:", binascii.hexlify(nonce), file=sys.stderr)
        print("Auth tag:", binascii.hexlify(auth_tag), file=sys.stderr)

        key = mk_key(password, salt)

        try:
            decrypted = decrypt(cipher_text, nonce, auth_tag, key)
            args.output.write(decrypted)
        except ValueError:
            print("Failed to decrypt. Please double check your password and try again", file=sys.stderr)

    else:
        raise Exception('Unknown operation {}'.format(args.op))


if __name__ == '__main__':
    main()
