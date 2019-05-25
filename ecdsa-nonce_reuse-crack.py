import hashlib
import base64
import binascii

try:
    from ecdsa.ecdsa import Signature
    from ecdsa.numbertheory import inverse_mod
    from ecdsa import SigningKey, VerifyingKey, der
except ImportError:
    raise ImportError("ECDSA tools are required. Use 'pip3 install -r requirements.txt' or 'pip install -r "
                      "requirements.txt' to install dependencies.")

# Debug Mode
verbosity = 0


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

    if verbosity >= 2:
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

    if verbosity >= 2:
        print("Hashing data : '{}'".format(data))

    _digest = algo()
    _digest.update(data)

    if verbosity >= 1:
        print("Hashed value : '{}'".format(str(binascii.hexlify(_digest.digest()))))

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

    if verbosity >= 2:
        print("Message : '{}'\n\thashed to : '{}'".format(msg_1, msg_1_int_hash))
        print("Message : '{}'\n\thashed to : '{}'".format(msg_2, msg_2_int_hash))

    return recover_signing_key(curve, msg_1_int_hash, sig_1, msg_2_int_hash, sig_2, hash_algo)


def recover_from_hash(curve, r, s1, h1, s2, h2, hashfunc):
    """

    :param curve:
    :param r:
    :param s1:
    :param h1:
    :param s2:
    :param h2:
    :param hashfunc:
    :return:
    """
    # Extract order from curve
    order = curve.order

    # Precomputed values for minor optimisation
    r_inv = inverse_mod(r, order)
    h = (h1 - h2) % order

    #
    # Signature is still valid whether s or -s mod curve_order (or n)
    # s*k-h
    # Try different possible values for "random" k until hit
    for k_try in (s1 - s2,
                  s1 + s2,
                  -s1 - s2,
                  -s1 + s2):

        # Retrieving actual k
        k = (h * inverse_mod(k_try, order)) % order

        if verbosity >= 2:
            print("Trying nonce value : '{}'".format(k))

        # Secret exponent
        secexp = (((((s1 * k) % order) - h1) % order) * r_inv) % order

        if verbosity >= 2:
            print("Secret exposant : '{}'".format(secexp))

        # Building the secret key
        signing_key = SigningKey.from_secret_exponent(secexp, curve=curve, hashfunc=hashfunc)

        if verbosity >= 2:
            print("Trying signing key : '{}'".format(signing_key.to_pem()))

        # Verify if build key is appropriate
        if signing_key.get_verifying_key().pubkey.verifies(h1, Signature(r, s1)):
            if verbosity >= 1:
                print("Success !")
            return signing_key

    return None


def recover_from_text(curve, r, s1, z1, s2, z2, hashfunc):
    """

    :param curve:
    :param r:
    :param s1:
    :param z1:
    :param s2:
    :param z2:
    :param hashfunc:
    :return:
    """

    h1 = int(binascii.hexlify(digest(hashfunc, z1)), 16)
    h2 = int(binascii.hexlify(digest(hashfunc, z2)), 16)

    return recover_from_hash(curve, r, s1, h1, s2, h2, hashfunc)


def recover_signing_key(curve, hash_1, sig_1, hash_2, sig_2, hashfunc):
    """
    Exploit Nonce-Reuse Vulnerability in ECDSA
    Tries to recover the signing key used in case of double nonce-use
    If not recovered, hits an assert
    :param curve: Curve used in ECDSA key in Curve type
    :param hash_1: int
    :param sig_1: Signature
    :param hash_2: int
    :param sig_2: Signature
    :param hashfunc: a hashlib hash algorithm
    :return: SigningKey
    """

    return recover_from_hash(curve, sig_1.r, sig_1.s, hash_1, sig_2.s, hash_2, hashfunc)


def sign(signing_key, message, hash_algo):
    """

    :param signing_key:
    :param message:
    :param hash_algo:
    :return:
    """
    # Get hash from message and convert it to integer
    _hash = digest(hash_algo, message)
    h_int = int(binascii.hexlify(_hash), 16)

    # Sign and get r and s
    r, s = signing_key.sign_number(h_int)

    # Build Signature
    return Signature(r, s)


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
    _hash = digest(hash_algo, message)
    h_int = int(binascii.hexlify(_hash), 16)
    r, s = signing_key.sign_number(h_int)
    d = der.encode_sequence(der.encode_integer(r), der.encode_integer(s))
    der_signature = base64.b64encode(d)

    if verbosity >= 2:
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

    return der_signature


def get_file_content(_file):
    """

    :param _file:
    :return:
    """
    with open(_file, 'r') as file:
        data = file.read()

    return data


def call_from_files(public_key_path, message1_path, message2_path, signature1_path, signature2_path, hash_alg):
    """

    :param public_key_path:
    :param message1_path:
    :param message2_path:
    :param signature1_path:
    :param signature2_path:
    :param hash_alg:
    :return:
    """
    pkey = get_file_content(public_key_path)
    msg1 = get_file_content(message1_path)
    msg2 = get_file_content(message2_path)
    sig1 = get_file_content(signature1_path)
    sig2 = get_file_content(signature2_path)

    # Transform PEM public key to python VerifyinKey type
    public_verification_key = VerifyingKey.from_pem(pkey.strip())

    # Launch exploit to try to get private key
    private_key = get_private_key(public_verification_key.curve,
                                  msg1.encode('utf-8'),
                                  sig1,
                                  msg2.encode('utf-8'),
                                  sig2,
                                  get_hash_function(hash_alg))

    return private_key


def test_chall_2():
    """

    :return:
    """
    from ecdsa.curves import NIST256p
    hash1 = '01b125d18422cdfa7b153f5bcf5b01927cf59791d1d9810009c70cd37b14f4e6'
    sig1_hex = '304402200861cce1da15fc2dd79f1164c4f7b3e6c1526e7e8d85716578689ca9a5dc349d02206cf26e2776f7c94cafcee05cc810471ddca16fa864d13d57bee1c06ce39a3188 '
    hash2 = '339ff7b1ced3a45c988b3e4e239ea745db3b2b3fda6208134691bd2e4a37d6e1'
    sig2_hex = '304402200861cce1da15fc2dd79f1164c4f7b3e6c1526e7e8d85716578689ca9a5dc349d02204ba75bdda43b3aab84b895cfd9ef13a477182657faaf286a7b0d25f0cb9a7de2'
    curve = NIST256p
    hash_algo = get_hash_function("sha256")

    sig1 = Signature

    int_h1 = int(hash1, 16)
    int_r = int(sig1_hex[:len(sig1_hex)//2], 16)
    int_s1 = int(sig1_hex[len(sig1_hex)//2:], 16)
    int_hash2 = int(hash2, 16)
    int_s2 = int(sig2_hex[len(sig2_hex)//2:], 16)

    print(recover_from_hash(curve, int_r, int_s1, int_h1, int_s2, int_hash2, hash_algo))

    print("out of chall")


def test_chall_1():
    """

    :return:
    """
    from ecdsa.curves import NIST192p
    hash1 = 78963682628359021178354263774457319969002651313568557216154777320971976772376
    s1 = 5416854926380100427833180746305766840425542218870878667299
    r1 = 5568285309948811794296918647045908208072077338037998537885
    hash2 = 62159883521253885305257821420764054581335542629545274203255594975380151338879
    s2 = 1063435989394679868923901244364688588218477569545628548100
    # r2 = 5568285309948811794296918647045908208072077338037998537885
    # n = 6277101735386680763835789423176059013767194773182842284081
    curve = NIST192p
    hash_algo = get_hash_function("sha256")

    print(recover_from_hash(curve, r1, s1, hash1, s2, hash2, hash_algo))

    print("out of chall")


def hardcoded_files():
    """
    python3 ecdsa-nonce_reuse-crack.py -files --pubkey ./tests/test1/pub.key --message1 ./tests/test1/message_1.txt \
    --message2 ./tests/test1/message_2.txt --signature1 ./tests/test1/signature_1.txt --signature2 \
    ./tests/test1/signature_2.txt --hashalg sha256
    """
    path = "./tests/test1/"
    pkey = path + "pub.key"
    msg1 = path + "message_1.txt"
    msg2 = path + "message_2.txt"
    sig1 = path + "signature_1.txt"
    sig2 = path + "signature_2.txt"
    hash_alg = "sha256"

    return call_from_files(pkey, msg1, msg2, sig1, sig2, hash_alg)


def hardcoded():
    """

    :return:
    """
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
    print("Private key is :\n\t{}".format(private_key.to_pem()))

    # Sign message
    print(sign(private_key, flag_clear.encode('utf-8'), hashing_algorithm))

    return private_key


def check_arguments(args):
    """

    :param args:
    :return:
    """
    def _build_missing_arg_error(command, arg_name):
        return "With {} command, {} argument needs to be defined.".format(command, arg_name)

    if args.verbosity > 0:
        global verbosity
        verbosity = args.verbosity

    if args.files:
        assert args.pubkey, _build_missing_arg_error("-files,", "--pubkey")
        assert args.message1, _build_missing_arg_error("-files", "--message1")
        assert args.message2, _build_missing_arg_error("-files", "--message2")
        assert args.signature1, _build_missing_arg_error("-files", "--signature1")
        assert args.signature2, _build_missing_arg_error("-files", "--signature2")

    elif args.cli:
        assert args.pk, _build_missing_arg_error("-files", "-pk")
        assert args.m1, _build_missing_arg_error("-files", "-m1")
        assert args.m2, _build_missing_arg_error("-files", "-m2")

        if args.sig1:
            assert args.sig2, "With -sig1, -sig2 must also be defined."
        elif args.sig2:
            assert args.sig1, "With -sig2, -sig1 must also be defined."
        else:
            if args.r:
                assert args.s1, "With -r s1 and s2 must both be defined."
                assert args.s2, "With -r s1 and s2 must both be defined."
            else:
                assert "If signatures are not given through -sig1 and -sig2, it is possible to give the common r and " \
                       "both remaining halfs of the signatures with -s1 and -s2. "
    elif args.hardcoded:
        return True

    return True


def conditional_exec(args):
    """

    :param args:
    :return:
    """

    if args.files:
        return call_from_files(args.pubkey,
                               args.message1,
                               args.message2,
                               args.signature1,
                               args.signature2,
                               args.hashalg)

    elif args.cli:
        print("cli")

    elif args.hardcoded:
        # return hardcoded()
        return test_chall_2()

    elif args.hardcoded_files:
        return hardcoded_files()


def parse():
    """

    :return:
    """
    import argparse
    parser = argparse.ArgumentParser(usage="",
                                     description="Retrieve ECDSA private key by exploiting a nonce-reuse in "
                                                 "signatures.",
                                     epilog="")

    verb = parser.add_mutually_exclusive_group()
    verb.add_argument("-q", "--quiet", action="store_true", help="Do not output anything on terminal (but errors and "
                                                                 "exceptions may still be printed). Private key will "
                                                                 "be printed in default file.")
    verb.add_argument("-v", "--verbosity", action="count", default=0,
                      help="increase output verbosity")

    commands = parser.add_mutually_exclusive_group(required=True)
    commands.add_argument("-files", action="store_true", default=False,
                          help="Specify this command if you want to read input from files.")
    commands.add_argument("-cli", action="store_true", default=False,
                          help="Specify this command if you want to read values directly from cli.")
    commands.add_argument("-hardcoded", action="store_true", default=False,
                          help="Modify values inside this script to operate.")
    commands.add_argument("-hardcoded-files", action="store_true", default=False,
                          help="Modify file names inside this script to operate.")

    # Files
    cmd_files = parser.add_argument_group('-files')

    cmd_files.add_argument("--pubkey", type=str, help="Path to the file containing a PEM encoded public key.")
    cmd_files.add_argument("--message1", type=str,
                           help="Path to the text file containing the first message that has been signed.")
    cmd_files.add_argument("--message2", type=str,
                           help="Path to the text file containing the second message that has been signed.")
    cmd_files.add_argument("--signature1", type=str,
                           help="Path to the text file containing the base64 encoded signature of the first message.")
    cmd_files.add_argument("--signature2", type=str,
                           help="Path to the text file containing the base64 encoded signature of the first message.")
    cmd_files.add_argument("--hashalg", type=str, choices=['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'md5'],
                           help="Hash algorithm used for the signatures.")
    cmd_files.add_argument("--ouput", type=str, default="./private.key",
                           help="Output file to print the private key to.")

    # CLI
    cmd_cli = parser.add_argument_group('-cli')
    cmd_cli.add_argument("-pk", type=str, help="PEM encoded public key.")
    cmd_cli.add_argument("-m1", type=str, help="First message that has been signed.")
    cmd_cli.add_argument("-m2", type=str, help="Second message that has been signed.")
    cmd_cli.add_argument("-sig1", type=str, help="Base64 encoded signature of the first message.")
    cmd_cli.add_argument("-sig2", type=str, help="Base64 encoded signature of the first message.")
    cmd_cli.add_argument("-alg", type=str, choices=['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'md5'],
                         help="Hash algorithm used for the signatures.")
    cmd_cli.add_argument("-o", type=str, default="./private.key", help="Output file to print the private key to.")
    cmd_cli.add_argument("-r", type=int, help="First half of the signature that is common in both signatures.")
    cmd_cli.add_argument("-s1", type=int, help="Second half of the signature of first message.")
    cmd_cli.add_argument("-s2", type=int, help="Second half of the signature of second message.")

    # Hardcoded
    _ = parser.add_argument_group('-hardcoded')

    # Hardcoded
    _ = parser.add_argument_group('-hardcoded-files')
    return parser


def main():
    # test_chall()

    args = parse().parse_args()
    check_arguments(args)

    if args.verbosity >= 2:
        print(args)

    if conditional_exec(args):
        print("Successfully recovered private key.")


if __name__ == "__main__":
    exit(main())
