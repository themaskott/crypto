#!/usr/bin/python3

import sys
import string
from Crypto.Random import random
import typing

CHAR_SET = string.printable[:-6]


def generate( size: int, alphabet: str ):
	return ''.join( random.choice(alphabet) for _ in range(size) )


if __name__ == "__main__":

	if len( sys.argv ) != 2:
		print(f"Usage : {sys.argv[0]} pass_lenght")
		exit( 1 )
	else:
		print( generate( int(sys.argv[1]), CHAR_SET ) )
		exit( 0 )
