# Cryptographie

## protec_multi.py : Chiffrement déchiffrement de fichier multi-destinataires

Protection d'un fichier pour un envoi multidestinataires.
Chiffrement / déchiffrement des données en AES-256-CBC.
La clef AES et l'iv sont générées aléatoirement, et transmises chiffrées avec les clefs publiques des destinataires (PKCS#1 OAEP).
L'intégrité des données est assurée par RSA (PKCS#1 PSS) en utilisant la clef privée de l'émetteur, appliqué sur la concatenation de l'ensemble des entêtes et des données chiffrées.

Structure du fichier chiffré :

```
| 0x00 | pub_key_recv_0_size | SHA256(pub_key_recv_0) | RSA( AES_sym_key + IV ) | <- dest 0
| 0x00 | pub_key_recv_1_size | SHA256(pub_key_recv_1) | RSA( AES_sym_key + IV ) | <- dest 1
| 0x00 | pub_key_recv_2_size | SHA256(pub_key_recv_2) | RSA( AES_sym_key + IV ) | <- dest 2
....
| 0x00 | pub_key_recv_n_size | SHA256(pub_key_recv_n) | RSA( AES_sym_key + IV ) | <- dest n
| 0x01 | ciphered_datas | message_signature
```

Pour chaque destinataire, les entêtes comprennent :
- la taille de la clef RSA du destinataire sur 2 octets (1024 ou 2048 bits)
- un identifiant permettant au destinataire de retrouver les éléments cryptographiques qui lui sont destinés (hash SHA256 de sa clef publique)
- la clef symétrique et l'iv utilisés pour chiffrer les données, chiffrés avec la clef publique du destinataire

Ces champs sont séparés par un octet nul `0x00` et la fin des entêtes est marquée par l'octet `0x01`.

```
usage: protect_multi.py [-h] [-e ENCRYPT] [-d DECRYPT] -pub PUBLIC [PUBLIC ...] -priv PRIVATE

Custom (de)cipher algorithm with assymetric integrity checking. Purpose is to send a secured file from one sender to multiple receivers. For encryption use sender private key and receivers public keys
files, including sender public key so he can retreive the message. For decryption use receiver private key and both receiver and sender public keys.

optional arguments:
  -h, --help            show this help message and exit
  -e ENCRYPT, --encrypt ENCRYPT
                        File to encrypt
  -d DECRYPT, --decrypt DECRYPT
                        File to decrypt
  -pub PUBLIC [PUBLIC ...], --public PUBLIC [PUBLIC ...]
                        Public keys files
  -priv PRIVATE, --private PRIVATE
                        Private key file
```

Le fichier à chiffrer (resp : déchiffrer) est passé en argument à `-e` (resp : `-d`), le resultat est sauvegardé dans un fichier `.enc` (resp : `.dec`).

Pour chiffrer un fichier, le programme prend en argument :
- `-e` : nom du fichier
- `-priv` : clef privée de l'émetteur utilisée pour signer le fichier
- `-pub` : les clefs publiques des destinataires, y compris celle de l'émetteur (afin d'assurer l'ouverture ultérieure du fichier par ce dernier)

Pour déchiffrer un fichier :
- `-d` : nom du fichier à déchiffrer
- `-priv` : clef privée du destinataire
- `-pub` : clef publiques du destinataire et de l'émetteur. Celle du destinataire lui permet de retrouver son id dans les entêtes, et celle de l'émetteur lui permet de retrouver la signature et contrôler l'intégrité du message.

Exemples : 
```
python3 protect_multi.py -e 896802.jpg -priv rsa_priv_4.pem -pub rsa_pub_1.pem rsa_pub_2.pem rsa_pub_3.pem rsa_pub_4.pem
[+] Ciphered in : 896802.jpg.enc
```
Ici, l'utilisateur n°4 adresse un fichier au n°1,2,3 et 4.
N°1,2,3 utilisent des clefs RSA de 2048 bits, le n°4 une clef de 1024 bits.

```
python3 protect_multi.py -d 896802.jpg.enc -priv rsa_priv_1.pem -pub rsa_pub_1.pem rsa_pub_4.pem
[+] Valid signature
[+] Deciphered in : 896802.jpg.enc.dec
```
L'utilisateur n°1 utilise sa clef privée pour déchiffrer le fichier, ainsi que sa clef publique et la clef publique de l'emetteur.
- `rsa_pub_1.pem` : permet au destinataire de retrouver son id dans les entêtes
- `rsa_pub_4.pem` : permet de connaitre la taille de clef utilisée par l'émetteur, et donc extraire la signature en fin de fichier, puis de vérifier l'intégrité du message
- `rsa_priv_1.pem` : permet au destinataire de déchiffrer la clef symétrique et l'iv.

Cas d'erreur :


```
python3 protect_multi.py -e 896802.jpg -priv rsa_priv_4.pem -pub rsa_pub_1.pem rsa_pub_2.pem rsa_pub_3.pem
[-] Private key doesn t match any of public keys
```
L'émetteur ne fournit pas sa clef publique.

```
python3 protect_multi.py -d 896802.jpg.enc -priv rsa_priv_1.pem -pub rsa_pub_2.pem rsa_pub_4.pem
[-] Private key doesn t match any of public keys
```
Le destinataire ne fournit pas un couple de clef valide.

```
python3 protect_multi.py -d 896802.jpg.enc -priv rsa_priv_1.pem -pub rsa_pub_1.pem rsa_pub_2.pem
[-] Invalid signature
```
Le destinataire ne fournit pas la bonne clef publique de l'émetteur.

```
python3 protect_multi.py -d 896802.jpg.enc -priv rsa_priv_1.pem -pub rsa_pub_1.pem rsa_pub_2.pem rsa_pub_4.pem
[-] Only two public keys are needed
```
Le destinataire fournit trop de clef pour le déchiffrement.



## protect_assymetric.py : Chiffrement déchiffrement de fichier / ASSYM

Chiffrement / déchiffrement des données en AES-256-CBC.
La clef AES et l'iv sont générées aléatoirement, et transmises chiffrées avec la clef publique du destinataire (PKCS#1 OAEP).
L'intégrité des données est assurée par RSA (PKCS#1 PSS) en utilisant la clef privée de l'émetteur, appliqué sur la concatenation de `RSA_pub_key(AES_key) + iv + chiper`

Le fichier de sortie contient :
`Signature + RSA_pub_key(AES_key) + iv + chiper`


```
usage: protect_assymetric.py [-h] [-e ENCRYPT] [-d DECRYPT] -pub PUBLIC -priv PRIVATE

Custom (de)cipher algorithm with assymetric integrity checking.
For encryption use sender private key and receiver public key file.
For decryption use receiver private key and sender public key.

optional arguments:
  -h, --help            show this help message and exit
  -e ENCRYPT, --encrypt ENCRYPT
                        File to encrypt
  -d DECRYPT, --decrypt DECRYPT
                        File to decrypt
  -pub PUBLIC, --public PUBLIC
                        Public key file
  -priv PRIVATE, --private PRIVATE
                        Private key file
```


## protect_symetric.py : Chiffrement déchiffrement de fichier / SYM

Chiffrement/déchiffrement d'un fichier en utilisant AES-256-CBC et contrôle de l'intégrité des données (HMAC-SHA256).

Attention, par raison de commodité le fichier à chiffrer est entièrement chargé en mémoire avant le chiffrement, ne convient pas au fichiers trop volumineux.

```
usage: protect_symetric.py [-h] [-e ENCRYPT] [-d DECRYPT] password

Custom (de)cipher algorithm

positional arguments:
  password              Passphrase

optional arguments:
  -h, --help            show this help message and exit
  -e ENCRYPT, --encrypt ENCRYPT
                        File to encrypt
  -d DECRYPT, --decrypt DECRYPT
                        File to decrypt

```



### Requirements

- pycryptodome
- binascii
- typing
- argparse
- pwntools (par facilité pour le packing en 32bits d'entiers, et l'affichage en console)
