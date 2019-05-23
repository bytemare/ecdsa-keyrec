import hashlib
import base64
import binascii

try:
    from ecdsa.ecdsa import Signature
    from ecdsa.numbertheory import inverse_mod
    from ecdsa import SigningKey, VerifyingKey, der
except ImportError:
    raise ImportError("ECDSA tools are required. Use 'pip3 install -r requirements.txt' or 'pip install -r requirements.txt' to install dependencies.")

# Debug Mode
debug = True

# Chose a hashing algorithm between : sha1, sha224, sha256, sha384, sha512 and md5
hashing_algorithm = "sha256"

# Some message to sign
flag_clear = "Please give me the flag"

# The Public key
public_key_pem = ''''
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpuXtxRVM66Bs0wooq288G3VXUHlr
bFTkMdbFM+SVYaFySfyUggFwTNKiDuTayOpLQNF6ypapU3eXBnIkWdcqSw==
-----END PUBLIC KEY-----
'''

# The faulty messages
message_1_cleartext = "he signed data). These assuran"
message_1_signature_der = "MEQCIDzdi89bc02mdxTxSo7tA8dmr3Xl0PrxugSy7KO93NR6AiArE3Hy" \
                          "+NPD3AYEuZTQy7vjzHVSLK0YsbEoPLZRZnI3fA==".strip()

message_2_cleartext = "ture verification process. A s"
message_2_signature_der = "MEUCIDzdi89bc02mdxTxSo7tA8dmr3Xl0PrxugSy7KO93NR6AiEAkhWDrap8G1x5mMSXJtdeJ56hx61G7sg4ojS" \
                          "+i4eabF4=".strip()


class UnknownHashAlgorithmError(Exception):
    pass


def rs_from_der(der_encoded_signature):
    """
    Given a DER encoded signature, returns the r and s factors
    DER format (in hex) :
    0x30 b1 0x02 b2 r 0x02 b3 s

    0x30    : 1-byte header (2 hex in string format)
    b1      : 1-byte header, length, in bytes, of the remaining list of bytes (from the first 0x02 to the end)

    0x02    : 1-byte header
    b2      : 1-byte indicating length, in bytes, of r value
    r       : r coordinate as big-endian positive signed integer (i.e. must start between 0x00 and 0x7F)

    0x02    : 1-byte header
    b3      : 1-byte indicating length, in bytes, of s value
    s       : s coordinate as big-endian positive signed integer (i.e. must start between 0x00 and 0x7F)

    INFO : After hitting my head against the wall and developing this to extract r and s by hand,
    I found out python-ecdsa had DER decoding functions for that. #RTFC

    :param der_encoded_signature:
    :return: r, s
    """

    # Look if library is available
    try:
        __import__("ecdsa.der")
    except ImportError:
        array = binascii.hexlify(base64.b64decode(der_encoded_signature))

        # r
        r_length = 2 * int(array[6:8], 16)
        r = array[8:8 + r_length]

        # s
        s_offset = 8 + r_length
        s = array[s_offset + 4:]

        # Cast them to integers
        # r = long(r, 16)
        # s = long(s, 16)
        r = int(r, 16)
        s = int(s, 16)

    else:
        rs, _ = der.remove_sequence(der.unpem(der_encoded_signature))
        r, tail = der.remove_integer(rs)
        # s, point_str_bitstring = der.remove_integer(tail)
        s, _ = der.remove_integer(tail)

    if debug:
        print("r : " + str(r))
        print("s : " + str(s))

    return r, s


def get_hash_function(hash_algo):
    """
    Given a string for hashing algorithm, returns the appropriate function
    :param hash_algo:
    :return:
    """

    if hash_algo == "sha1":
        return hashlib.sha1

    elif hash_algo == "sha224":
        return hashlib.sha224

    elif hash_algo == "sha256":
        return hashlib.sha256

    elif hash_algo == "sha384":
        return hashlib.sha384

    elif hash_algo == "sha512":
        return hashlib.sha512

    elif hash_algo == "md5":
        return hashlib.md5

    else:
        raise UnknownHashAlgorithmError


def digest(hash_algo, data):
    """
    Given a algorithm, hashes the content
    :param hash_algo:
    :param data:
    :return:
    """
    if isinstance(hash_algo, str):
        algo = get_hash_function(hash_algo)
    else:
        algo = hash_algo

    _digest = algo()
    _digest.update(data)
    return _digest.digest()


def get_private_key(curve, msg_1, sign_1, msg_2, sign_2, hash_algo):
    """
    Wrapper function to recover_private_key
    :param curve: Curve used in ECDSA key in Curve type
    :param msg_1: Cleartext message string
    :param sign_1: Base64 encoded signature of msg_1
    :param msg_2: Cleartext message string
    :param sign_2: Base64 encoded signature of msg_2
    :param hash_algo: hashlib type of used hashing algorithm
    :return:
    """

    # Build Signature types from decoded DER signatures
    sig_1 = Signature(*rs_from_der(sign_1))
    sig_2 = Signature(*rs_from_der(sign_2))

    # Get hashes from messages and convert them to integer
    # Gmsg_1_int_hash = long(binascii.hexlify(digest(hash_algo, msg_1)), 16)
    # Gmsg_2_int_hash = long(binascii.hexlify(digest(hash_algo, msg_2)), 16)
    msg_1_int_hash = int(binascii.hexlify(digest(hash_algo, msg_1)), 16)
    msg_2_int_hash = int(binascii.hexlify(digest(hash_algo, msg_2)), 16)

    return recover_private_key(curve, msg_1_int_hash, sig_1, msg_2_int_hash, sig_2, hash_algo)


def recover_private_key(curve, hash_1, sig_1, hash_2, sig_2, hash_algo):
    """
    Exploit Nonce-Reuse Vulnerability in ECDSA
    Tries to recover the private key used for signing in case of double nonce-use
    If not recovered, hits an assert
    :param curve: Curve used in ECDSA key in Curve type
    :param hash_1: int
    :param sig_1: Signature
    :param hash_2: int
    :param sig_2: Signature
    :param hash_algo: a hashlib hash algorithm
    :return:
    """

    # Extract order from curve
    order = curve.order

    # Precompute values for minor optimisation
    sig_1_r_inv = inverse_mod(sig_1.r, order)
    z = (hash_1 - hash_2) % order

    #
    # Signature is still valid whether s or -s mod curve_order (or n)
    # s*k-h
    # Try different possible values for "random" k until hit
    for k_try in (sig_1.s - sig_2.s,
                  sig_1.s + sig_2.s,
                  -sig_1.s - sig_2.s,
                  -sig_1.s + sig_2.s):

        # Retrieving actual k
        k = (z * inverse_mod(k_try, order)) % order

        # Secret exponent
        secexp = (((((sig_1.s * k) % order) - hash_1) % order) * sig_1_r_inv) % order

        # Building the secret key
        secret_key = SigningKey.from_secret_exponent(secexp, curve=curve, hashfunc=hash_algo)

        if debug:
            print("[DBG] Trying k : " + str(k))

        # Verify if build key is appropriate
        if secret_key.get_verifying_key().pubkey.verifies(hash_1, sig_1):
            return secret_key

    assert False, "Could not recover corresponding private key"


def sign_in_der(signing_key, message, hash_algo):
    """
    Given a SigningKey and message, signs the latter and encodes signature into DER format
    Parts of code are taken from ecdsa library
    :param signing_key:
    :param message:
    :param hash_algo:
    :return:
    """

    # Get hash from message and convert it to integer
    hash = digest(hash_algo, message)
    h_int = int(binascii.hexlify(hash), 16)
    r, s = signing_key.sign_number(h_int)
    d = der.encode_sequence(der.encode_integer(r), der.encode_integer(s))
    der_signature = base64.b64encode(d)

    if debug:
        print("")
        print("[DBG] hash (hex) : " + str(binascii.hexlify(hash)))
        print("[DBG] r (" + str(len(str(hex(r)))) + ") : " + str(hex(r)))
        print("[DBG] s (" + str(len(str(hex(s)))) + ") : " + str(hex(s)))
        print("[DBG] hex : " + str(binascii.hexlify(d)))
        print("[DBG] der : " + str(der_signature))

        sig = Signature(*rs_from_der(der_signature))
        assert signing_key.get_verifying_key().pubkey.verifies(h_int,
                                                               sig), "Message signed but verification failed !"
        print("Message successfully verified.")

    return base64.b64encode(d)


def get_file_content(_file):
    """
    """
    with open(_file, 'r') as file:
        data = file.read()
    
    return data


def call_from_files(public_key_path, message1_path, message2_path, signature1_path, signature2_path, hash_alg):
    pkey=get_file_content(public_key_path)
    msg1=get_file_content(message1_path)
    msg2=get_file_content(message2_path)
    sig1=get_file_content(signature1_path)
    sig2=get_file_content(signature2_path)

    # Transform PEM public key to python VerifyinKey type
    public_verification_key = VerifyingKey.from_pem(pkey.strip())

    # Launch exploit to try to get private key
    private_key = get_private_key(public_verification_key.curve,
                                  msg1.encode('utf-8'),
                                  sig1,
                                  msg2.encode('utf-8'),
                                  sig2,
                                  get_hash_function(hashing_algorithm))
    
    return private_key

    # Print the recovered private key
    #print(private_key.to_pem())

    # Sign message
    #print(sign_in_der(private_key, flag_clear.encode('utf-8'), hashing_algorithm))


def test_chall():
    from ecdsa.curves import NIST192p
    z1 = "78963682628359021178354263774457319969002651313568557216154777320971976772376".encode('utf-8')
    s1 = 5416854926380100427833180746305766840425542218870878667299
    r1 = 5568285309948811794296918647045908208072077338037998537885
    z2 = "62159883521253885305257821420764054581335542629545274203255594975380151338879".encode('utf-8')
    s2 = 1063435989394679868923901244364688588218477569545628548100
    r2 = 5568285309948811794296918647045908208072077338037998537885
    n = 6277101735386680763835789423176059013767194773182842284081
    curve = NIST192p
    hash_algo = get_hash_function("md5")

    # Build Signature types from r and s
    sig_1 = Signature(r1, s1)
    sig_2 = Signature(r2, s2)

    # Compute hashes
    msg_1_int_hash = int(binascii.hexlify(digest(hash_algo, z1)), 16)
    msg_2_int_hash = int(binascii.hexlify(digest(hash_algo, z1)), 16)

    private_key = recover_private_key(curve, msg_1_int_hash, sig_1, msg_2_int_hash, sig_2, hash_algo)

    print("out of chall")


def test_hardcoded():
    # Transform PEM public key to python VerifyinKey type
    public_verification_key = VerifyingKey.from_pem(public_key_pem.strip())

    # Launch exploit to try to get private key
    private_key = get_private_key(public_verification_key.curve,
                                  message_1_cleartext.encode('utf-8'),
                                  message_1_signature_der,
                                  message_2_cleartext.encode('utf-8'),
                                  message_2_signature_der,
                                  get_hash_function(hashing_algorithm))

    # Print the recovered private key
    print(private_key.to_pem())

    # Sign message    
    print(sign_in_der(private_key, flag_clear.encode('utf-8'), hashing_algorithm))


def parse():
    import argparse
    parser = argparse.ArgumentParser(description="Retrieve ECDSA private key by exploiting a nonce-reuse in signatures.")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-q", "--quiet", action="store_true", help="Do not output anything on terminal (but errors and exceptions may still be printed). Private key will be printed in default file.")
    group.add_argument("-v", "--verbosity", action="count", default=0,
                        help="increase output verbosity")

    parser.add_argument("-pk", "--pubkey", type=str, help="Path to the file containing a PEM encoded public key.")
    parser.add_argument("-m1", "--message1", type=str, help="Path to the text file containing the first message that has been signed.")
    parser.add_argument("-m2", "--message2", type=str, help="Path to the text file containing the second message that has been signed.")
    parser.add_argument("-s1", "--signature1", type=str, help="Path to the text file containing the base64 encoded signature of the first message.")
    parser.add_argument("-s2", "--signature2", type=str, help="Path to the text file containing the base64 encoded signature of the first message.")
    parser.add_argument("-alg", "--hashalg", type=str, choices=['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'md5'], help="Hash algorithm used for the signature.")
    parser.add_argument("-o", "--ouput", type=str, default="./private.key", help="Output file to print the private key to.")

    return parser

def test_files():
    """
    python3 ecdsa-nonce_reuse-crack.py -pk ./tests/test1/pub.key -m1 ./tests/test1/message_1.txt -m2 ./tests/test1/message_2.txt -s1 ./tests/test1/signature_1.txt -s2 ./tests/test1/signature_2.txt -alg sha256
    """
    path="./tests/test1/"
    pkey=path + "pub.key"
    msg1=path + "message_1.txt"
    msg2=path + "message_2.txt"
    sig1=path + "signature_1.txt"
    sig2=path + "signature_2.txt"
    hash_alg="sha256"

    return call_from_files(pkey, msg1, msg2, sig1, sig2, hash_alg)

if __name__ == "__main__":

    #test_chall()

    #test_hardcoded()

    #test_files()
    args = parse().parse_args()
    print(args)

    private_key = call_from_files(args.pubkey,
                                    args.message1,
                                    args.message2,
                                    args.signature1,
                                    args.signature2,
                                    args.hashalg)
    
    print(private_key.to_pem())

    print(sign_in_der(private_key, flag_clear.encode('utf-8'), hashing_algorithm))
