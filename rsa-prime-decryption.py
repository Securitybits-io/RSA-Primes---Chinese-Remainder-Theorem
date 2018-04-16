#!/usr/bin/python
#!c:\python27\python.exe

# -*- coding: ascii -*-

"""
RSA Encryption operation using the Chinese Remainder Theorem
Ref: Wikipedia

p and q are used for key generation
dp = d (mod p-1)
dq = d (mod q-1)
qinv = q^-1

m1 = c^dp
m2 = c^dq
h = qinv(m1 - m2) (mod p)
m = m2 + h * q
------------
References: 
RSA CryptoSystem         https://en.wikipedia.org/wiki/RSA_(cryptosystem)
Decrypting RSA using CRT http://www.cscjournals.org/manuscript/Journals/IJCSS/Volume10/Issue5/IJCSS-1289.pdf
Modular inverse example  https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python

"""

__author__ = 'Christoffer Claesson (Christoffer.Claesson@Securitybits.io)'
__copyright__ = 'Copyright (c) 2018 Christoffer Claesson'
__license__ = 'GNUPG'
__vcs_id__ = '$Id$'
__version__ = '1.0.0' #Versioning: http://www.python.org/dev/peps/pep-0386/

#Imports
import argparse

#Variables
c,p,q,dp,dq = 0,0,0,0,0         #instantiate variables

#Functions
def initiate_argparse():
    parser = argparse.ArgumentParser(description='Decryption tool for RSA Primes using the Chinese Remainder Theorem')
    parser.add_argument('--p', type=int, help='Input prime p used for RSA decryption')
    parser.add_argument('--q', type=int, help='Input prime q used for RSA Decryption')
    parser.add_argument('--dp', type=int, help='Input Chinese Remainder dp used for RSA decryption')
    parser.add_argument('--dq', type=int, help='Input Chinese Remainder dq used for RSA Decryption')
    parser.add_argument('--c', type=int, help='Input Cipher text to decrypt')

    return parser.parse_args()

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modular_inverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def decrypt_rsa(p,q,dp,dq,c):
    qinv = modular_inverse(q, p)
    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)
    h = (qinv * (m1 - m2)) % p
    m = m2 + h * q
    return m

def decode_plaintext(plaintext):
    decoded = ''.join([chr(int(''.join(c), 16)) for c in zip(plaintext[0::2],plaintext[1::2])])
    return decoded

def main():
    args = initiate_argparse()
    p = args.p
    q = args.q
    dp = args.dp
    dq = args.dq
    c =  args.c
    decrypted_cipher = hex(decrypt_rsa(p,q,dp,dq,c))[2:]
    plaintext = decode_plaintext(decrypted_cipher)
    print("Decrypted ciphertext: " + str(decrypted_cipher).strip("L"))
    print("Plaintext: " + str(plaintext))
    pass

if __name__=='__main__':
    main()
