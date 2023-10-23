import math
import point
from curve import secp256k1


def add1(x1, y1, x2, y2):
    #Point(x=None, y=None, curve=secp256k1)
    P: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    if x1 != x2:
        slope: int = (((y2 - y1) % P) / ((x2 - x1) % P)) %P
        x3 = (((slope ** 2) % P - x1) % P - x2) % P
        y3 = ((slope * ((x1 - x3) % P)) % P - y1) % P
    if x1 == x2 and y1 == y2:
        print (x1**2)
        slope: int = (3 * x1 ** 2 + 0) / (2 * y1)
        x3 = slope ** 2 - 2 * x1
        y3 = slope * (x1 - x3) - y1
    return x3, y3


def add(x1, y1, x2, y2):
    #Point(x=None, y=None, curve=secp256k1)
    point1 = point.Point(x1, y1, curve=secp256k1)
    point2 = point.Point(x2, y2, curve=secp256k1)
    combined = point1 + point2
    return combined.x.value, combined.y.value

def mul(x1, y1, scalar):
    x = x1
    y = y1
    xr: int = None
    yr: int = None
    while scalar:
        if scalar & 1:  # same as scalar % 2
            if xr is not None and yr is not None:
                xr, yr = add(xr, yr, x, y)  # result = result + current
            else:
                xr = x
                yr = y
        x, y = add(x, y, x, y)  # current = current + current  # point doubling
        scalar >>= 1  # same as scalar / 2
    return xr, yr
