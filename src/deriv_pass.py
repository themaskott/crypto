#!/usr/bin/python3

import sys
import binascii
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import typing
from pwn import p32

NB_ITER = 500
SALT_LENGTH = 6

def generate_salt( size: int ):
	return get_random_bytes( size )

def deriv_password( password: bytes, sel: bytes, counter: int ):
	buffer = password + sel + p32(0x00)
	h = SHA256.new()
	h.update( buffer )
	for i in range( 1, counter ):
		buffer = h.digest() + password + sel + p32(i)
		h.update( buffer )
	return h.digest()


if __name__ == "__main__":
	if len( sys.argv ) != 2:
		print(f"Usage : {sys.argv[0]} password")
		exit( 1 )
	else:
		sel = generate_salt( SALT_LENGTH )
		hash = deriv_password( sys.argv[1].encode(), sel, NB_ITER )
		print("$" + binascii.hexlify(sel).decode() + "$" + binascii.hexlify(hash).decode() )
		exit( 0 )
