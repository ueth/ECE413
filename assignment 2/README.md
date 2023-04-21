# Assign 2

Secure Server-Client Program using OpenSSL in C.

## How to install

First install OpenSSL for Ubuntu

Then generate certifivate with the command: openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mycert.pem -out mycert.pem

* req                -> Primarily creates and processes certificate requests in PKCS#10 format.
* -x509              -> This option outputs a self signed certificate instead of a certificate request.
* -nodes             -> When this option is specified then if a private key is created it will not be encrypted.
* -days 365          -> when the -x509 option is being used this specifies the number of days to certify the certificate for.
* -newkey rsa:2048   -> Creates a new certificate request and a new private key. (rsa:2048 generates an RSA key with 2048 number of bits)
* -keyout mycert.pem -> This gives the filename to write the newly created private key to.
* -out mycert.pem    -> This specifies the output filename to write to or standard output by default.

## Compile

To compile server.c and client.c all at once use make.

## How to run

First run the server: sudo ./server 8082

* sudo because only root user can run the server.
* 8082 is the port number.

Then run the client: ./client 127.0.0.1 8082

* 127.0.0.1: Local IP address.
* 8082 is the port number.

## GCC Version

gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0