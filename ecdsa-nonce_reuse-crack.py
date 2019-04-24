import hashlib
import base64
import binascii

from ecdsa.ecdsa import Signature
from ecdsa.numbertheory import inverse_mod
from ecdsa import SigningKey, VerifyingKey, der

# Debug Mode
debug = True

# Chose a hashing algorithm between : sha1, sha224, sha256, sha384, sha512 and md5
hashing_algorithm = "sha256"

# The ECW flag to sign
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
    I found out python-ecdsa had der functions for that. #RTFC

    :param der_encoded_signature:
    :return: r, s
    """
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
        r = long(r, 16)
        s = long(s, 16)

    else:
        rs, _ = der.remove_sequence(der.unpem(der_encoded_signature))
        r, tail = der.remove_integer(rs)
        s, point_str_bitstring = der.remove_integer(tail)

    # print("r : " + str(r))
    # print("s : " + str(s))

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
    algo = get_hash_function(hash_algo)
    _digest = algo()
    _digest.update(data)
    return _digest.digest()


def get_private_key(verification_key, msg_1, sign_1, msg_2, sign_2, hash_algo):
    """
    Wrapper function to recover_private_key
    :param verification_key: Public ECDSA key in VerficationKey type
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
    msg_1_int_hash = long(binascii.hexlify(digest(hash_algo, msg_1)), 16)
    msg_2_int_hash = long(binascii.hexlify(digest(hash_algo, msg_2)), 16)

    return recover_private_key(verification_key, msg_1_int_hash, sig_1, msg_2_int_hash, sig_2, hash_algo)


def recover_private_key(verification_key, hash_1, sig_1, hash_2, sig_2, hash_algo):
    """
    Exploit Nonce-Reuse Vulnerability in ECDSA
    Tries to recover the private key used for signing in case of double nonce-use
    If not recovered, hits an assert
    :param verification_key:
    :param hash_1:
    :param sig_1:
    :param hash_2:
    :param sig_2:
    :param hash_algo:
    :return:
    """

    # Extract curve info from public key
    curve = verification_key.curve
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
        secret_key = SigningKey.from_secret_exponent(secexp, curve=curve, hashfunc=get_hash_function(hash_algo))

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
    h = get_hash_function(hash_algo)(message).digest()
    h_int = int(binascii.hexlify(h), 16)
    r, s = private_key.sign_number(h_int)
    d = der.encode_sequence(der.encode_integer(r), der.encode_integer(s))
    der_signature = base64.b64encode(d)

    if debug:
        print("")
        print("[DBG] hash (hex) : " + str(binascii.hexlify(h)))
        print("[DBG] r (" + str(len(str(hex(r)))) + ") : " + str(hex(r)))
        print("[DBG] s (" + str(len(str(hex(s)))) + ") : " + str(hex(s)))
        print("[DBG] hex : " + binascii.hexlify(d))
        print("[DBG] der : " + der_signature)

        sig = Signature(*rs_from_der(der_signature))
        assert signing_key.get_verifying_key().pubkey.verifies(h_int,
                                                               sig), "Message signed but verification failed !"
        print("Message successfully verified.")

    return base64.b64encode(d)


if __name__ == "__main__":

    # Transform PEM public key to python VerifyinKey type
    public_verification_key = VerifyingKey.from_pem(public_key_pem.strip())

    # Launch exploit to try to get private key
    private_key = get_private_key(public_verification_key,
                                  message_1_cleartext,
                                  message_1_signature_der,
                                  message_2_cleartext,
                                  message_2_signature_der,
                                  hashing_algorithm)

    # Print the recovered private key
    print(private_key.to_pem())

    # Sign ECW Flag
    flag_signed = sign_in_der(private_key, flag_clear, hashing_algorithm)
    
    print(sign_in_der(private_key, flag_clear, hashing_algorithm))
