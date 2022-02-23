#!/usr/bin/python3

# Chiffrement de donnees en utilisant AES-256-CBC
# Controle de l integrite en utilisant HMAC-SHA256
# Attention : a utiliser dans un but educatif uniquement

# @Maskott
# 03/02/2022


import sys
import binascii
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import typing
import argparse
from pwn import p32, log

AES256_KEY_SIZE = 32
NB_ITER = 500
SALT_LENGTH = 3
KC_CSTE = 0xdeadbeef
KI_CSTE = 0x1337babe


def generate_salt() -> bytes:
	"""
	Genere un sel de taille SALT_LENGTH
	"""
	return get_random_bytes( SALT_LENGTH )

def generate_iv():
	"""
	Genere un vecteur d initialisation pour AES
	"""
	return get_random_bytes( AES.block_size )

def deriv_password( password: bytes, sel: bytes, counter: int ) -> bytes:
	"""
	Fonction de derivation de mot de passe
	Genere une clef maitre
	"""
	buffer = password + sel + p32(0x00)
	h = SHA256.new()
	h.update( buffer )
	for i in range( 1, counter ):
		buffer = h.digest() + password + sel + p32(i)
		h.update( buffer )
	return h.digest()

def deriv_key( Km: bytes ) -> bytes:
	"""
	Fonction de derivation de clef
	A partir d une clef maitre retourne une clef de chiffrement et une clef d integrite
	"""
	h = SHA256.new()
	h.update( Km + p32(KC_CSTE))
	Kc = h.digest()

	h = SHA256.new()
	h.update( Km + p32(KI_CSTE))
	Ki = h.digest()

	return Kc, Ki

def encrypt( plain_file: str, password:bytes ):
	"""
	Chiffrement d un fichier utilisant AES-256-CBC
	Le fichier de sortie contient : HMAC || iv || sel || chiffre
	"""
	# Generation des elements crypto
	salt = generate_salt()
	Km = deriv_password( password, salt, NB_ITER )
	Kc, Ki = deriv_key( Km )
	iv = generate_iv()

	# Initialisation du chiffrement
	cipher = AES.new(Kc, AES.MODE_CBC, iv)

	# Lecture des donnees claires
	with open( plain_file, "rb" ) as pf:
		plain_buffer = pf.read()

	# Chiffrement
	ciphered_buffer = cipher.encrypt( pad(plain_buffer, AES.block_size) )

	# Signature de iv | sel | ciphered
	h = HMAC.new(Ki, digestmod=SHA256)
	h.update( iv + salt + ciphered_buffer )
	with open( plain_file + ".enc", "wb" ) as cf:
		cf.write( h.digest() + iv + salt + ciphered_buffer )

	log.success("Ciphered in : " + plain_file + ".enc")


def decrypt( ciphered_file: str, password: str):
	"""
	Dechiffrement d un fichier utilisant AES-256-CBC
	Recupere les entetes HMAC pour la verification, l iv et le sel
	"""
	# Recuperation des elements crypto et du chiffre
	with open( ciphered_file, "rb") as cf:
		hmac = cf.read( AES256_KEY_SIZE )
		iv = cf.read( AES.block_size )
		salt = cf.read( SALT_LENGTH )
		ciphered_buffer = cf.read()

	# Reconstitution des clefs
	Km = deriv_password( password, salt, NB_ITER )
	Kc, Ki = deriv_key( Km )

	# Initialisation du dechiffrement
	cipher = AES.new(Kc, AES.MODE_CBC, iv)

	# verification de la signature
	h = HMAC.new(Ki, digestmod=SHA256)
	h.update( iv + salt + ciphered_buffer )
	try:
		h.verify(hmac)
		log.success("Correct signature")
	except ValueError:
		log.failure("Incorrect signature")
		sys.exit(1)

	# Dechiffrement
	plain_buffer = unpad( cipher.decrypt( ciphered_buffer ), AES.block_size )

	# Ecriture du clair
	with open( ciphered_file + ".dec", "wb") as pf:
		pf.write( plain_buffer )

	log.success("Deciphered in : " + ciphered_file + ".dec")


def getArgParseur():
	"""
	Gestion des arguments passes en ligne de commande
	"""
	argparseur = argparse.ArgumentParser( add_help=True, description="Custom (de)cipher algorithm" )
	argparseur.add_argument( "password", help="Passphrase" )
	argparseur.add_argument( "-e", "--encrypt", dest="encrypt", help="File to encrypt", required=False )
	argparseur.add_argument( "-d", "--decrypt", dest="decrypt", help="File to decrypt", required=False )
	return argparseur


if __name__ == "__main__":

	args = getArgParseur().parse_args()

	if args.decrypt and args.encrypt:
		print("Wrong usage can't encrypt and decrypt simultaneously")
		sys.exit(1)

	if args.encrypt:
		encrypt( args.encrypt, args.password.encode() )

	if args.decrypt:
		decrypt( args.decrypt, args.password.encode() )

	sys.exit(0)
