import argparse

def parse_args():
    parser = argparse.ArgumentParser("Encrypt and decrypt files using AES")
    parser.add_argument('op', choices=['enc', 'dec'], help="operation to perform, (enc)rypt or (dec)rypt")
    parser.add_argument('-i', required=True, dest='input', type=argparse.FileType('rb'), help="input file")
    parser.add_argument('-o', required=True, dest='output', type=argparse.FileType('wb'), help="output file")
    args = parser.parse_args()
    return args
