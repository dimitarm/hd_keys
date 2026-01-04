import hmac

from cryptography.hazmat.primitives.asymmetric import ec
from curve import secp256k1
from point import G, Point
from signature import PrivateKey, Signature
from ec_arithmetic import add
import hashlib
import base58
from random import randint
import segwit_addr


# secp256k1 multiplication - public key
# returns the coordinate pair resulting from EC point multiplication (repeated application of the EC group operation) of
# the secp256k1 base point with the integer p.
def point(p: int) -> tuple[int, int]:
    pubnumbers = ec.derive_private_key(p, ec.SECP256K1()).public_key().public_numbers()
    return pubnumbers.x, pubnumbers.y


def ser32(i) -> bytearray:
    return i.to_bytes(4, 'big')


def ser256(p) -> bytearray:
    return p.to_bytes(32, 'big')


# serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's compressed form: (0x02 or 0x03) || ser256(x),
# where the header byte depends on the parity of the omitted y coordinate.
def serp(x: int, y: int) -> bytes:
    if y % 2 == 0:
        prefix = bytes([2])
    else:
        prefix = bytes([3])
    return prefix + x.to_bytes(32, 'big')


def parse256(p) -> int:
    assert len(p) == 32, "length is: " + str(len(p))
    return int.from_bytes(p, 'big')


def CKDpriv(kpar: int, cpar: bytes, i: int) -> tuple[int, bytes]:
    if i >= 2 ** 31:
        data = bytes([0]) + ser256(kpar) + ser32(i)
    else:
        x, y = point(kpar)
        data = serp(x, y) + ser32(i)

    l = hmac.digest(cpar, data, "sha512")

    il = l[0:32]
    ir = l[32:]
    n: int = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    i32bytes: int = parse256(il)
    ki = (i32bytes + kpar) % n
    if i32bytes >= n or ki == 0:
        raise OverflowError()

    return ki, ir


def CKDpub(xKpar: int, yKpar: int, cpar: bytes, i: int) -> tuple[int, int, bytes]:
    if i >= 2 ** 31:
        raise ValueError("Can't create hardened public key")

    data = serp(xKpar, yKpar) + ser32(i)
    l = hmac.digest(cpar, data, "sha512")
    il = l[0:32]
    ir = l[32:]
    xl, yl = point(parse256(il))
    xki, yki = add(xl, yl, xKpar, yKpar)
    return xki, yki, ir


def seed(mnemonic: bytes, passwd: bytes) -> bytes:
    dk = hashlib.pbkdf2_hmac('sha512', mnemonic, b'mnemonic' + passwd, 2048)
    return dk


def master_pair(seed: bytes) -> tuple[int, bytes]:
    l = hmac.digest(b'Bitcoin seed', seed, "sha512")
    il = l[0:32]
    ir = l[32:]
    return parse256(il), ir


# fingerprint of parent public
def key_identifier(x: int, y: int) -> bytes:
    ident = serp(x, y)
    ripemd_hasher = hashlib.new('ripemd160')
    ripemd_hasher.update(hashlib.sha256(ident).digest())
    hash = ripemd_hasher.digest()
    return hash[:4]


def serialize_key(public: bool, depth: int, index: int, chain_code: bytes,
                  key: bytes, parent_key_identifier: bytes) -> bytes:
    assert len(chain_code) == 32
    assert (public and len(key) == 33) or (not public and len(key) == 32)
    assert len(parent_key_identifier) == 4

    if public:
        result = bytes([0x04, 0xb2, 0x47, 0x46]) #bytes([0x04, 0x88, 0xB2, 0x1E])
    else:
        result = bytes([0x04, 0xb2, 0x43, 0x0c]) #bytes([0x04, 0x88, 0xAD, 0xE4])

    result = result + depth.to_bytes(1, 'big')
    result = result + parent_key_identifier

    result = result + index.to_bytes(4, 'big')
    result = result + chain_code
    if public:
        result = result + key
    else:
        result = result + bytes([0]) + key
    return base58.b58encode_check(result)


def generate_child_private_key(parent: dict, index: int, depth: int) -> dict:
    key, chain_code = CKDpriv(parent["key"], parent["code"], index)
    path = parent["path"] + '/'
    if index >= 2 ** 31:
        path = path + str(index - 2 ** 31) + '\''
    else:
        path = path + str(index)
    parent_key_identifier = key_identifier(parent["x"], parent["y"])
    serialized_key = serialize_key(False, depth, index, chain_code,
                                   key.to_bytes(32, 'big'), parent_key_identifier)
    publ_x, publ_y = point(key)
    publ_key = serp(publ_x, publ_y)
    serialized_public_key = serialize_key(True, depth, index, chain_code,
                                   publ_key, parent_key_identifier)
    print(path + ' serialized private key: ' + serialized_key.decode('ascii') + ' serialized public key: ' + serialized_public_key.decode('ascii') + ' public key: ' + publ_key.hex() + ' private key: ' + hex(key) + ' address:' + generate_bech32(publ_key))
    return {"key": key, "code": chain_code, "x": publ_x, "y": publ_y, "path": path}


def generate_bech32(public_key):
    ripemd_hasher = hashlib.new('ripemd160')
    d = hashlib.sha256(public_key).digest()
    ripemd_hasher.update(d)
    spk = ripemd_hasher.digest()
    version = 0
    return segwit_addr.encode('bc', version, spk)


def generate_child_public_key(parent: dict, index: int, depth: int) -> dict:
    path = parent["path"] + '/' + str(index)
    x, y, chain_code = CKDpub(parent["x"], parent["y"], parent["code"], index)
    parent_key_identifier = key_identifier(parent["x"], parent["y"])
    serialized_key = serialize_key(True, depth, index, chain_code, serp(x, y), parent_key_identifier)
    print(path + ' serialized public key: ' + serialized_key.decode('ascii') + ' key: ' + serp(x, y).hex() + ' address:' + generate_bech32(serp(x, y)))
    return {"x": x, "y": y, "code": chain_code, "path": path}


def get_public_key_tuple(source_key:dict, parent: dict, index: int, depth: int):
    path = source_key["path"] + '/' + str(index)
    parent_key_identifier = key_identifier(parent["x"], parent["y"])
    serialized_key = serialize_key(True, depth, index, source_key["code"], serp(source_key["x"], source_key["y"]), parent_key_identifier)
    print(path + '     key: ' + serialized_key.decode('ascii'))
    return {"x": source_key["x"], "y": source_key["y"], "code": source_key["code"], "path": path}


def check_key_pair(key: int, x: int, y: int):
    e = PrivateKey(key)  # generate a private key
    #pub = e.secret * G  # public point corresponding to e
    x, y = point(key)
    pub = Point(x, y, G.curve)
    z = randint(0, 2 ** 256)  # generate a random message for testing
    signature: Signature = e.sign(z)
    assert signature.verify(z, pub)


def main():
    default_mnemonic = "stuff damp margin flip shoulder box split father bird join grocery volume"
    prompt = f"Enter mnemonic phrase (press Enter to use default: \"{default_mnemonic}\"): "
    user_mnemonic = input(prompt).strip()
    mnemonic = user_mnemonic or default_mnemonic

    main_seed = seed(mnemonic.encode('utf-8'), b'')

    print('seed: ' + main_seed.hex())
    root_key, root_chain_code = master_pair(main_seed)
    print('root_key: ' + str(hex(root_key)))
    root_key_serialized = serialize_key(False, 0, 0, root_chain_code,
                                        root_key.to_bytes(32, 'big'), bytes([0, 0, 0, 0]))
    print('root private key serialized: ' + root_key_serialized.decode('ascii'))

    root_publ_x, root_publ_y = point(root_key)
    root = {"key": root_key, "code": root_chain_code, "x": root_publ_x, "y": root_publ_y, "path": 'm'}

    root_public_key_serialized = serialize_key(True, 0, 0, root_chain_code, serp(root_publ_x, root_publ_y), bytes([0, 0, 0, 0]))
    print('root public key serialized: ' + root_public_key_serialized.decode('ascii'))

    print()
    #derivation
    derivation_schema = 84
    m44 = generate_child_private_key(root, 2 ** 31 + derivation_schema, 1)
    print()
    m44_0 = generate_child_private_key(m44, 2 ** 31, 2)
    print()
    m44_0_0 = generate_child_private_key(m44_0, 2 ** 31, 3)  # account key
    print()
    m44_0_0_1 = generate_child_private_key(m44_0_0, 1, 4)
    print()
    m44_0_0_0 = generate_child_public_key(m44_0_0, 0, 4)
    m44_0_0_0_0 = generate_child_public_key(m44_0_0_0, 0, 5)
    m44_0_0_1_0 = generate_child_private_key(m44_0_0_1, 0, 5)

    m44_0_0_0_1 = generate_child_public_key(m44_0_0_0, 1, 5)
    m44_0_0_1_1 = generate_child_private_key(m44_0_0_1, 1, 5)
    check_key_pair(m44_0_0_1_1["key"], m44_0_0_0_1["x"], m44_0_0_0_1["y"])


if __name__ == "__main__":
    main()
