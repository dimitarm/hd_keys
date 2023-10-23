from dataclasses import dataclass
from random import randint

from point import G, N, Point


@dataclass
class PrivateKey:
    secret: int

    def sign(self, z: int) -> "Signature":
        e = self.secret
        k = randint(0, N)
        R = k * G
        r = R.x.value
        k_inv = pow(k, -1, N)  # Python 3.8+
        s = ((z + r * e) * k_inv) % N

        return Signature(r, s)


@dataclass
class Signature:
    r: int
    s: int

    def verify(self, z: int, pub_key: Point) -> bool:
        s_inv = pow(self.s, -1, N)  # Python 3.8+
        u = (z * s_inv) % N
        v = (self.r * s_inv) % N

        return (u * G + v * pub_key).x.value == self.r
