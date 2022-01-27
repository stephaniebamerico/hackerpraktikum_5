#!/usr/bin/env python3

import base64
import sys

# " DEST #31337 END"
injection = bytes.fromhex('20444553542023333133333720454e44')

if __name__ == '__main__':
    # " DEST #78384 END"
    original_plaintext = sys.stdin.readline().strip()
    original_plain_fourthblock = original_plaintext[-16:].encode('utf-8')

    # stores the request (base64 and aes-only)
    original_request = sys.stdin.readline().strip()
    original_aes = base64.b64decode(original_request)

    # stores the last block, after aes decryption, but before xor (DEC[i])
    fourthblock_postaes_prexor = bytearray(16)
    for i in range(0, 16):
        # calculate the block by XORing the last-1 encrypted block and last plaintext block
        fourthblock_postaes_prexor[i] = original_aes[32+i] ^ original_plain_fourthblock[i]

    new_thirdblock = bytearray(16)
    for i in range(0, 16):
        # XOR the DEC[i] and our injection plaintext block
        new_thirdblock[i] = fourthblock_postaes_prexor[i] ^ injection[i]

    # at this point, at the decryption of the last block:
    #  ENC[i] is passed through AES decryption and results in DEC[i]
    #  DEC[i] is XORed with new_thirdblock (ENC[i-1]) and then results in injection

    new_aes = original_aes[0:32] + new_thirdblock + original_aes[48:64]
    new_request = base64.b64encode(new_aes)

    print(new_request.decode('utf-8'))
