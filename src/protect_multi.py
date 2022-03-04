#!/usr/bin/python3

# Chiffrement de donnees en utilisant AES-256-CBC
# Controle de l integrite en utilisant RSA
# Attention : a utiliser dans un but educatif uniquement

# Envoi de fichier chiffré et signé multi destinataire

# @Maskott
# 22/02/2022

# Structure du fichier chiffré :

"""
| 0x00 | pub_key_recv_0_size (2 octets) | id = SHA256(pub_key_recv_0) | RSA( AES_sym_key + IV ) |  <-- dest 0 (ie sender)
| 0x00 | pub_key_recv_1_size (2 octets) | id = SHA256(pub_key_recv_1) | RSA( AES_sym_key + IV ) |  <-- dest 1
| 0x00 | pub_key_recv_2_size (2 octets) | id = SHA256(pub_key_recv_2) | RSA( AES_sym_key + IV ) |
....
| 0x00 | pub_key_recv_n_size (2 octets) | id = SHA256(pub_key_recv_n) | RSA( AES_sym_key + IV ) |  <-- dest n
| 0x01 | ciphered_datas | message_signature

"""


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
SHA256_LENGTH = 32


def generate_key() -> bytes:
	"""
	Genere une clef de taille AES256_KEY_SIZE
	"""
	return get_random_bytes( AES256_KEY_SIZE )


def generate_iv() -> bytes:
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

def rsa_verify( key_file: str, message: bytes, signature:bytes ) -> bool:
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

def rsa_check_keys_encrypt( priv_key_file: str, pub_key_file_list: str) -> bool:
	"""
	Verifie les clefs fournient pour le chiffrement
	Au moins deux clefs publiques (expediteur et au moins un destinataire)
	La clef privee doit former un couple valide avec l une des clefs publiques
	"""
	if len( args.public ) < 2 :
		log.failure("At least two public keys are needed")
		sys.exit(1)

	priv_key = RSA.importKey(open(priv_key_file).read())
	for pub_key_file in pub_key_file_list:
		if priv_key.publickey() == RSA.importKey(open(pub_key_file).read()):
			return True

	log.failure("Private key doesn t match any of public keys")
	sys.exit(1)

def rsa_check_keys_decrypt( priv_key_file: str, pub_key_file_list: str)->bool:
	"""
	Verifie les clefs fournient pour le dechiffrement
	Exactement deux clefs publiques (destinataire et expediteur)
	La clef privee doit former un couple valide avec la clef publique du destinataire
	"""

	if len( args.public ) != 2 :
		log.failure("Exactly two public keys are needed")
		sys.exit(1)

	priv_key = RSA.importKey(open(priv_key_file).read())
	if priv_key.publickey() != RSA.importKey(open(pub_key_file_list[0]).read()) and priv_key.publickey() != RSA.importKey(open(pub_key_file_list[1]).read()):
		log.failure("Private key doesn t match any of public keys")
		sys.exit(1)		

	return True


def rsa_order_key_decrypt( priv_key_file: str, pub_key_file_list: str ) -> str:
	"""
	Dans le cas du dechiffrement, identifie la clef publique du destinataire et celle de l emetteur
	Les retourne ordonnees
	"""
	priv_key = RSA.importKey(open(priv_key_file).read())
	if priv_key.publickey() == RSA.importKey(open(pub_key_file_list[0]).read()):
		return pub_key_file_list[0], pub_key_file_list[1]
	else:
		return pub_key_file_list[1], pub_key_file_list[0]


def encrypt( plain_file: str, priv_key_file: str, pub_key_file_list: str ):
	"""
	Chiffrement d un fichier utilisant AES-256-CBC
	"""

	ciphered_buffer = b''

	# generation des secrets
	Kc = generate_key()
	iv = generate_iv()

	# initialisation de AES
	cipher = AES.new(Kc, AES.MODE_CBC, iv)

	# constitution de l entete de fichier chiffre
	for pub_key_file in pub_key_file_list:
		RSA_PUB_MODULUS_SIZE = int( RSA.importKey(open(pub_key_file).read()).size_in_bits() )
		
		h = SHA256.new()
		h.update( open(pub_key_file,"rb").read()) 
		
		ciphered_buffer += b'\x00'
		ciphered_buffer += RSA_PUB_MODULUS_SIZE.to_bytes(2, byteorder="big")
		ciphered_buffer += h.digest()
		ciphered_buffer += rsa_encrypt(pub_key_file, Kc + iv )

	ciphered_buffer += b'\x01'


	# Recuperation des donnes claires
	with open( plain_file, "rb" ) as pf:
		plain_buffer = pf.read()

	# chiffrement des donnees
	ciphered_buffer += cipher.encrypt( pad(plain_buffer, AES.block_size) )

	# signature de l ensemble des entetes et du chiffre
	signature = rsa_sign( priv_key_file, ciphered_buffer )

	# Ecriture des donnes de chiffrement et du chiffre
	with open( plain_file + ".enc", "wb" ) as cf:
		cf.write( ciphered_buffer + signature )

	log.success("Ciphered in : " + plain_file + ".enc")


def decrypt( ciphered_file: str, priv_key_file: str, pub_key_file_list: str ):
	"""
	Dechiffrement d un fichier utilisant AES-256-CBC
	Recupere les entetes pour la verification et le dechiffrement : signature, clef, iv
	"""

	# Identification des clefs publiques
	pub_key_file_receiver, pub_key_file_sender = rsa_order_key_decrypt( priv_key_file, pub_key_file_list )

	# Calcul de la taille de modulus RSA necessaire pour lecture des bons offsets dans le fichier
	# pur l extraction de la signature en fin de fichier
	RSA_PUB_MODULUS_SIZE = int( RSA.importKey(open(pub_key_file_sender).read()).size_in_bits() / 8 )

	# Recuperation des elements crypto
	with open( ciphered_file, "rb") as cf:
		ciphered_buffer = cf.read()

	signature = ciphered_buffer[-RSA_PUB_MODULUS_SIZE:]

	# verification de l integrite
	verif = rsa_verify( pub_key_file_sender, ciphered_buffer[:-RSA_PUB_MODULUS_SIZE], signature )
	if not verif:
		sys.exit(1)
	
	# Calcul de l id du destinataire a rechercher dans les entetes
	h = SHA256.new()
	h.update( open(pub_key_file_receiver,"rb" ).read()) 
	receiver_id = h.digest()
	
	# Parcours des entetes
	is_legit = False
	cursor = 0
	separator = ciphered_buffer[ cursor ]

	while separator == 0x00:
		key_size = int( int.from_bytes(ciphered_buffer[ cursor + 1 : cursor + 3 ], "big") / 8 )
		if receiver_id == ciphered_buffer[ cursor + 3 : cursor + 3 + SHA256_LENGTH ]:
			aes_key_iv_ciphered = ciphered_buffer[ cursor + 3 + SHA256_LENGTH : cursor + 3 + SHA256_LENGTH + key_size ]
			is_legit = True

		cursor = cursor + 3 + SHA256_LENGTH + key_size
		separator = ciphered_buffer[ cursor ]

	if not is_legit:
		log.failure("You are not a legit receiver")
		sys.exit(1)

	encrypted_data = ciphered_buffer[ cursor + 1 : -RSA_PUB_MODULUS_SIZE]

	aes_key_iv = rsa_decrypt( priv_key_file, aes_key_iv_ciphered )

	Kc = aes_key_iv[ 0 : AES256_KEY_SIZE ]
	iv = aes_key_iv[ -AES.block_size : ]

	# Dechiffrement des donnees
	cipher = AES.new(Kc, AES.MODE_CBC, iv)
	plain_buffer = unpad( cipher.decrypt( encrypted_data ), AES.block_size )

	# Exriture des donnees dechiffrees
	with open( ciphered_file + ".dec", "wb") as pf:
		pf.write( plain_buffer )

	log.success("Deciphered in : " + ciphered_file + ".dec")


def getArgParseur( ):
	"""
	Gestion des arguments passes en ligne de commande
	"""
	argparseur = argparse.ArgumentParser( add_help=True, description="""Custom (de)cipher algorithm with assymetric integrity checking.
																		Purpose is to send a secured file from one sender to multiple receivers.
																		For encryption use sender private key and receivers public keys files,
																		including sender public key so he can retreive the message.
																		For decryption use receiver private key and both receiver and sender public keys.
																		""" )
	argparseur.add_argument( "-e", "--encrypt", dest="encrypt", help="File to encrypt", required=False )
	argparseur.add_argument( "-d", "--decrypt", dest="decrypt", help="File to decrypt", required=False )
	argparseur.add_argument( "-pub", "--public", nargs='+', dest="public", help="Public keys files", required=True )
	argparseur.add_argument( "-priv", "--private", dest="private", help="Private key file", required=True )

	return argparseur


if __name__ == "__main__":

	args = getArgParseur().parse_args()

	if args.decrypt and args.encrypt:
		print("Wrong usage can't encrypt and decrypt simultaneously")
		sys.exit(1)

	if args.encrypt and rsa_check_keys_encrypt( args.private, args.public ):
		encrypt( args.encrypt, args.private, args.public )

	if args.decrypt and rsa_check_keys_decrypt( args.private, args.public ):
		decrypt( args.decrypt, args.private, args.public )

	sys.exit(0)
