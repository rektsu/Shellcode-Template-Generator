#!/bin/python3

import sys
import os
import hashlib
import string
import argparse

class Encryptor:
    def __init__(self, bin, key):
        self.bin = bin
        self.key = key

    def xor(self):
        length = len(self.key)
        output_str = ""

        for i in range(len(self.bin)):
            current_data = self.bin[i]
            current_key = self.key[i % len(self.key)]
            ordd = lambda x: x if isinstance(x, int) else ord(x)
            output_str += chr(ordd(current_data) ^ ord(current_key))
        return output_str

    def xor_encrypt(self):
        ciphertext = self.xor()
        ciphertext = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };'
        print(ciphertext)
        return ciphertext, self.key


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Shellcode template generator tool')
    parser.add_argument('-b', '--binary', dest='binary', required=True, help='select path of your binary', type=str)
    parser.add_argument('-k', '--key', dest='key', required=True, help='select the key to cypher your shellcode', type=str)
    parser.add_argument('-w', '--overwrite', action='store_true', required=False, help='select this option to write the shellcode in the malware file youre coding')
    parser.add_argument('-c', '--cypher', dest='cypher', choices=['xor', 'aes'], required=True, help='the cypher you want to apply, i.e: XOR, AES')
    parser.add_argument('-o', '--output', action='store_true', required=False, help='select this option if you want to write the generated shellcode in a .txt file')

    args = parser.parse_args()

    if args.cypher == 'xor':
        payload = open(args.binary, "rb").read()
        key = args.key
        shell_xor_enc = Encryptor(payload, key)
        ciphertext, p_key = shell_xor_enc.xor_encrypt()








