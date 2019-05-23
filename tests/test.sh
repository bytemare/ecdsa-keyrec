#!/usr/bin/env sh

# Test with hardcoded values
./python ../ecdsa-nonce_reuse-crack.py -hardcoded || ./python3 ../ecdsa-nonce_reuse-crack.py -hardcoded

# Test with files
args="-files --pubkey ./tests/test1/pub.key --message1 ./tests/test1/message_1.txt --message2 ./tests/test1/message_2.txt --signature1 ./tests/test1/signature_1.txt --signature2 ./tests/test1/signature_2.txt --hashalg sha256"
./python ../ecdsa-nonce_reuse-crack.py "$args" || ./python3 ../ecdsa-nonce_reuse-crack.py "$args"

# Test with command line arguments
echo "TODO : cli"