# Assign 1

Simple implementation of Diffie-Hellman Key Exchange and RSA (Rivest–Shamir–Adleman).

## How to run dh_assign_1

You can run dh_assign_1 by using this example: ./dh_assign_1 -o output.txt -p 23 -g 9 -a 15 -b 2
* output.txt     -> Path to the output file
* p              -> Prime number
* g              -> Base
* a              -> Secret integer A
* b              -> Secret integer B

## How to run rsa_assign_1

In order to run rsa_assign_1 first generate private and public key pairs using: ./rsa_assign_1 -g

To encrypt: ./rsa_assign_1 -i plaintext.txt -o ciphertext.txt -k public.key -e
* plaintext.txt  -> Text to encrypt
* ciphertext.txt -> Save encrypted message
* public.key     -> Path to the public key file

To decrypt: ./rsa_assign_1 -i ciphertext.txt -o decrypted.txt -k private.key -d
* ciphertext.txt -> Text to decrypt
* decrypted.txt  -> Save decrypted message
* private.key    -> Path to the private key file

## GCC Version

gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0

### Note

What to improve:
* p and q could be better randomized with bigger range
* e could have better randomization
* Random prime generator could be faster with a stronger algorithm