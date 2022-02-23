#!/usr/bin/python3

import sys
import string
from Crypto.Random import get_random_bytes
from base64 import b64encode
import binascii
import typing



def generate( size: int ):
	return get_random_bytes( size )


if __name__ == "__main__":

	if len( sys.argv ) != 2:
		print(f"Usage : {sys.argv[0]} key_lenght")
		exit( 1 )
	else:
		print( binascii.hexlify( generate( int(sys.argv[1]) ) ).decode() )
		print( b64encode( generate( int(sys.argv[1]) ) ).decode() )
		exit( 0 )
