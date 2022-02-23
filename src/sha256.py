#!/usr/bin/python3

import argparse
import binascii
from Crypto.Hash import SHA256
import typing

BUFFER_SIZE = 1024

# getArgPArseur
# utilisation de argparse pour recupere les arguments au lancement du programme
def getArgParseur( ):
	"""
	Gestion des arguments passes en ligne de commande
	"""
	argparseur = argparse.ArgumentParser( add_help=True, description="Compute sha25 hash" )
	argparseur.add_argument( "-f", "--file", dest="file", help="File to hash", required=False )
	argparseur.add_argument( "-s", "--string", help="String to hash", required=False )

	return argparseur



def hash_file( filename: str ):
	h = SHA256.new()
	with open( filename,"rb" ) as fi:
		buffer = fi.read( BUFFER_SIZE )
		while buffer:
			h.update( buffer )
			buffer = fi.read( BUFFER_SIZE )
	return h.digest()

def hash_string( string: str ):
	h = SHA256.new()
	h.update( string )
	return h.digest()

def main( args ):

	if ( args.file ):
		print( binascii.hexlify(hash_file( args.file ) ).decode() )
	if( args.string ):
		print( binascii.hexlify(hash_string( args.string.encode() ) ).decode() )




if __name__ == "__main__":
	args = getArgParseur().parse_args()
	main( args )
