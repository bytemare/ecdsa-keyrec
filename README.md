# ecdsa-keyrec
[![Build Status](https://travis-ci.org/bytemare/ecdsa-keyrec.svg?branch=master)](https://travis-ci.com/bytemare/ecdsa-keyrec)

A python script enabling private key recovery from signatures by implementing an attack on ECDSA nonce-reuse.

Sample text, public key, and signed messages are given for test and example.

NB: beware of newlines if you're using files, and if you really want them there. Newlines in signature files might not be supported, you might as well strip them.

Needed package : ecdsa

``` shell
pip3 install ecdsa
```

Usage and arguments:
```
$ python3 ecdsa-nonce_reuse-crack.py -h
usage: 

Retrieve ECDSA private key by exploiting a nonce-reuse in signatures.        

optional arguments:
  -h, --help            show this help message and exit
  -q, --quiet           Do not output anything on terminal (but errors and   
                        exceptions may still be printed). Private key will be
                        printed in default file.
  -v, --verbosity       increase output verbosity
  -files                Specify this command if you want to read input from  
                        files.
  -cli                  Specify this command if you want to read values      
                        directly from cli.
  -hardcoded            Modify values inside this script to operate.
  -hardcoded-files      Modify file names inside this script to operate.     

-files:
  --pubkey PUBKEY       Path to the file containing a PEM encoded public key.
  --message1 MESSAGE1   Path to the text file containing the first message   
                        that has been signed.
  --message2 MESSAGE2   Path to the text file containing the second message  
                        that has been signed.
  --signature1 SIGNATURE1
                        Path to the text file containing the base64 encoded  
                        signature of the first message.
  --signature2 SIGNATURE2
                        Path to the text file containing the base64 encoded  
                        signature of the first message.
  --hashalg {sha1,sha224,sha256,sha384,sha512,md5}
                        Hash algorithm used for the signatures.
  --output OUTPUT       Output file to print the private key to.

-cli:
  -pk PK                PEM encoded public key.
  -m1 M1                First message that has been signed.
  -m2 M2                Second message that has been signed.
  -sig1 SIG1            Base64 encoded signature of the first message.       
  -sig2 SIG2            Base64 encoded signature of the first message.       
  -alg {sha1,sha224,sha256,sha384,sha512,md5}
                        Hash algorithm used for the signatures.
  -o O                  Output file to print the private key to.
  -r R                  First half of the signature that is common in both   
                        signatures.
  -s1 S1                Second half of the signature of first message.
  -s2 S2                Second half of the signature of second message.
```
