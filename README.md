# Python AWS Examples

Based on https://cryptobook.nakov.com/symmetric-key-ciphers/aes-encrypt-decrypt-examples

## Setup

Using virtualenv:

```sh
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```sh
# Encrypt
python aes-gcm.py enc -i examples/lock.jpg -o examples/lock.aes

# Decrypt
python aes-gcm.py dec -i examples/lock.aes -o examples/lock.dec.jpg
```
