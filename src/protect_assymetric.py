#!/usr/bin/python3

# Chiffrement de donnees en utilisant AES-256-CBC
# Controle de l integrite en utilisant RSA
# Attention : a utiliser dans un but educatif uniquement

# @Maskott
# 03/02/2022


import sys
import binascii
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import typing
import argparse
from pwn import p32, log

AES256_KEY_SIZE = 32


def generate_key():
	"""
	Genere une clef de taille AES256_KEY_SIZE
	"""
	return get_random_bytes( AES256_KEY_SIZE )


def generate_iv():
	"""
	Genere un vecteur d initialisation pour AES
	"""
	return get_random_bytes( AES.block_size )

def rsa_encrypt( key_file: str, buffer: bytes ) -> bytes:
	"""
	Chiffre le buffer avec RSA
	"""
	key = RSA.importKey(open(key_file).read())
	cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
	return cipher.encrypt(buffer)

def rsa_decrypt( key_file: str, buffer: bytes ) -> bytes:
	"""
	Dechiffre le buffer avec RSA
	"""
	key = RSA.importKey(open(key_file).read())
	cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
	return cipher.decrypt(buffer)

def rsa_sign( key_file: str, message: bytes ) -> bytes:
	"""
	Signe un message avec RSA
	"""
	key = RSA.importKey(open(key_file).read())
	h = SHA256.new(message)
	return pss.new(key).sign(h)

def rsa_verify( key_file: str, message: bytes, signature:bytes )->bool:
	"""
	Verifie une signature RSA
	"""
	key = RSA.importKey(open(key_file).read())
	h = SHA256.new(message)
	checker = pss.new(key)
	try:
		checker.verify(h, signature)
		log.success("Valid signature")
		return True
	except ValueError:
		log.failure("Invalid signature")
		return False


def encrypt( plain_file: str, priv_key_file: str, pub_key_file: str ):
	"""
	Chiffrement d un fichier utilisant AES-256-CBC
	Le fichier de sortie contient : SignRSA || RSA(Kc) || iv || chiffre
	"""
	# generation des secrets
	Kc = generate_key()
	iv = generate_iv()

	# initialisation de AES
	cipher = AES.new(Kc, AES.MODE_CBC, iv)

	# Recuperation des donnes claires
	with open( plain_file, "rb" ) as pf:
		plain_buffer = pf.read()

	# chiffrement des donnees
	ciphered_buffer = cipher.encrypt( pad(plain_buffer, AES.block_size) )

	# chiffrement de la clef sym
	ciphered_key = rsa_encrypt(pub_key_file, Kc)

	# signature de Kc|iv|ciphered
	signature = rsa_sign( priv_key_file, ciphered_key + iv + ciphered_buffer )

	# Ecriture des donnes de chiffrement et du chiffre
	with open( plain_file + ".enc", "wb" ) as cf:
		cf.write( signature + ciphered_key + iv + ciphered_buffer )

	log.success("Ciphered in : " + plain_file + ".enc")


def decrypt( ciphered_file: str, priv_key_file: str, pub_key_file: str ):
	"""
	Dechiffrement d un fichier utilisant AES-256-CBC
	Recupere les entetes pour la verification et le dechiffrement : signature, clef, iv
	"""
	# Calcul des tailles de modulus RSA necessaires pour lecture des bons offsets dans le fichier
	RSA_PRIV_MODULUS_SIZE = int( RSA.importKey(open(priv_key_file).read()).size_in_bits() / 8 )
	RSA_PUB_MODULUS_SIZE = int( RSA.importKey(open(pub_key_file).read()).size_in_bits() / 8 )

	# Recuperation des elements crypto
	with open( ciphered_file, "rb") as cf:
		signature = cf.read( RSA_PUB_MODULUS_SIZE )
		ciphered_key = cf.read( RSA_PRIV_MODULUS_SIZE  )
		iv = cf.read( AES.block_size )
		ciphered_buffer = cf.read()

	# verification de l integrite
	verif = rsa_verify( pub_key_file, ciphered_key + iv + ciphered_buffer, signature )
	if not verif:
		sys.exit(1)

	# dechiffrement de la clef symetrique
	Kc = rsa_decrypt( priv_key_file, ciphered_key )

	# Dechiffrement des donnees
	cipher = AES.new(Kc, AES.MODE_CBC, iv)
	plain_buffer = unpad( cipher.decrypt( ciphered_buffer ), AES.block_size )

	# Exriture des donnees dechiffrees
	with open( ciphered_file + ".dec", "wb") as pf:
		pf.write( plain_buffer )

	log.success("Deciphered in : " + ciphered_file + ".dec")


def getArgParseur( ):
	"""
	Gestion des arguments passes en ligne de commande
	"""
	argparseur = argparse.ArgumentParser( add_help=True, description="""Custom (de)cipher algorithm with assymetric integrity checking.
																		For encryption use sender private key and receiver public key file.
																		For decryption use receiver private key and sender public key.
																		""" )
	argparseur.add_argument( "-e", "--encrypt", dest="encrypt", help="File to encrypt", required=False )
	argparseur.add_argument( "-d", "--decrypt", dest="decrypt", help="File to decrypt", required=False )
	argparseur.add_argument( "-pub", "--public", dest="public", help="Public key file", required=True )
	argparseur.add_argument( "-priv", "--private", dest="private", help="Private key file", required=True )

	return argparseur


if __name__ == "__main__":

	args = getArgParseur().parse_args()

	if args.decrypt and args.encrypt:
		print("Wrong usage can't encrypt and decrypt simultaneously")
		sys.exit(1)

	if args.encrypt:
		encrypt( args.encrypt, args.private, args.public )

	if args.decrypt:
		decrypt( args.decrypt, args.private, args.public )

	sys.exit(0)
