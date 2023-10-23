from random import randint

from curve import secp256k1
from point import G, I, N, Point
from signature import PrivateKey, Signature

# Test case 1
assert N * G == I

# Test case 2
pub = Point(
    x=0x9577FF57C8234558F293DF502CA4F09CBC65A6572C842B39B366F21717945116,
    y=0x10B49C67FA9365AD7B90DAB070BE339A1DAF9052373EC30FFAE4F72D5E66D053,
    curve=secp256k1,
)
e: int = 2 ** 240 + 2 ** 31
assert e * G == pub

#  Test case 3
pub = Point(
    x=0x887387E452B8EACC4ACFDE10D9AAF7F6D9A0F975AABB10D006E4DA568744D06C,
    y=0x61DE6D95231CD89026E286DF3B6AE4A894A3378E393E93A0F45B666329A0AE34,
    curve=secp256k1,
)

# Test case 3.1: verify authenticity
z = 0xEC208BAA0FC1C19F708A9CA96FDEFF3AC3F230BB4A7BA4AEDE4942AD003C0F60
r = 0xAC8D1C87E51D0D441BE8B3DD5B05C8795B48875DFFE00B7FFCFAC23010D3A395
s = 0x68342CEFF8935EDEDD102DD876FFD6BA72D6A427A3EDB13D26EB0781CB423C4

assert Signature(r, s).verify(z, pub)

# Test case 3.2: verify authenticity for different signature w/ same P
z = 0x7C076FF316692A3D7EB3C3BB0F8B1488CF72E1AFCD929E29307032997A838A3D
r = 0xEFF69EF2B1BD93A66ED5219ADD4FB51E11A840F404876325A1E8FFE0529A2C
s = 0xC7207FEE197D27C618AEA621406F6BF5EF6FCA38681D82B2F06FDDBDCE6FEAB6
assert Signature(r, s).verify(z, pub)

# Test case 3.3: sign and verify
e = PrivateKey(randint(0, N))  # generate a private key
pub = e.secret * G  # public point corresponding to e
z = randint(0, 2 ** 256)  # generate a random message for testing
signature: Signature = e.sign(z)
assert signature.verify(z, pub)
