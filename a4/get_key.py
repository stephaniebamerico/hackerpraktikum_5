#!/usr/bin/env python3

from ecdsa import SigningKey, VerifyingKey, der, NIST256p, numbertheory
from ecdsa.util import sigdecode_der, string_to_number
import hashlib

if __name__ == '__main__':
    message1 = open("msg1.txt", "rb").read()
    message2 = open("msg2.txt", "rb").read()
    signature1 = open("msg1.sig", "rb").read()
    signature2 = open("msg2.sig", "rb").read()

    z1 = string_to_number(hashlib.sha1(message1).digest())
    z2 = string_to_number(hashlib.sha1(message2).digest())

    signature1, garbage = der.remove_sequence(signature1)
    signature2, garbage = der.remove_sequence(signature2)

    r1, signature1 = der.remove_integer(signature1)
    s1, garbage = der.remove_integer(signature1)

    r2, signature2 = der.remove_integer(signature2)
    s2, garbage = der.remove_integer(signature2)

    assert r1 == r2, 'Signatures do not share the same nonce!'

    k = (((z1-z2) % NIST256p.order)*(numbertheory.inverse_mod((s1-s2) % NIST256p.order, NIST256p.order))) % NIST256p.order

    privkey_hex = hex((((((s1*k) % NIST256p.order) - z1) % NIST256p.order)*numbertheory.inverse_mod(r1, NIST256p.order)) % NIST256p.order)[2:]

    PrivKey = SigningKey.from_string(bytes().fromhex(privkey_hex), curve=NIST256p)

    print(PrivKey.to_pem().decode('utf-8'))
