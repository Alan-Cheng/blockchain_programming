# Purpose: Elliptic Curve Cryptography

import hashlib
import hmac

class FieldElement:
    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = f"Num {num} not in field range 0 to {prime - 1}"
            raise ValueError(error)
        self.num = num
        self.prime = prime
    def __repr__(self):
        return f"FieldElement_{self.prime}({self.num})"
    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime
    def __ne__(self, other):
        if other is None:
            return True
        return self.num != other.num or self.prime != other.prime
    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot add two numbers in different Fields")
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)
    
    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot add two numbers in different Fields")
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)
    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot add two numbers in different Fields")
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)
    def __pow__(self, exponent):
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)
    def __truediv__(self, other):
        num = self.num * pow(other.num, self.prime - 2, self.prime) % self.prime
        return self.__class__(num, self.prime)
    
    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num, self.prime)
    def __repr__(self):
        return "FieldElement_{}({})".format(self.prime, self.num)
    
class Point:
    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        if self.x is None and self.y is None:
            return
        if self.y**2 != self.x**3 + a * x + b:
            raise ValueError(f"({x}, {y}) is not on the curve")
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y \
            and self.a == other.a and self.b == other.b
    def __ne__(self, other):
        return self.x != other.x or self.y != other.y \
            or self.a != other.a or self.b != other.b   
    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError(f"Points {self}, {other} are not on the same curve")
        if self.x is None:
            return other
        if other.x is None:
            return self
        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)
        if self.x != other.x:
            s = (other.y - self.y) / (other.x - self.x)
            x = s**2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)
        if self == other:
            s = (3 * self.x**2 + self.a) / (2 * self.y)
            x = s**2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)
    def repr__(self):
        if self.x is None:
            return "Point(infinity)"
        else:
            return "Point({},{})_{}".format(self.x.num, self.y.num, self.x.prime)
        
    def __rmul__(self, coefficient):
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result
    
p = 2**256 - 2**32 - 977

class S256Field(FieldElement):
    def __init__(self, num, prime=None):
        super().__init__(num, p)
    def __repr__(self):
        return "{:x}".format(self.num).zfill(64)
    def sqrt(self):
        return self**((p + 1) // 4)

A = 0
B = 7
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

class S256Point(Point):
    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(S256Field(x), S256Field(y), a, b)
        else:
            super().__init__(x, y, a, b)
    def __rmul__(self, coefficient):
        coef = coefficient % N
        return super().__rmul__(coef)
    
    def verify(self, z, sig):
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        total = u * G + v * self
        return total.x.num == sig.r
    def sec(self, compressed=True):
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        return b'\x04' + self.x.num.to_bytes(32, 'big') \
            + self.y.num.to_bytes(32, 'big')
    @classmethod
    def parse(self, sec_bin):
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33:65], 'big')
            return S256Point(x, y)
        is_even = sec_bin[0] == 2
        x = S256Field(int.from_bytes(sec_bin[1:], 'big'))
        alpha = x**3 + S256Field(B)
        beta = alpha.sqrt()
        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = S256Field(p - beta.num)
        else:
            even_beta = S256Field(p - beta.num)
            odd_beta = beta
        if is_even:
            return S256Point(x, even_beta)
        else:
            return S256Point(x, odd_beta)
    
G = S256Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

class Signature:
    def __init__(self, r, s):
        self.r = r
        self.s = s
    def __repr__(self):
        return "Signature({:x}, {:x})".format(self.r, self.s)
    def der(self):
        rbin = self.r.to_bytes(32, 'big')
        rbin = rbin.lstrip(b'\x00')
        if rbin[0] & 0x80:
            rbin = b'\x00' + rbin
        result = bytes([2, len(rbin)]) + rbin
        sbin = self.s.to_bytes(32, 'big')
        sbin = sbin.lstrip(b'\x00')
        if sbin[0] & 0x80:
            sbin = b'\x00' + sbin
        result += bytes([2, len(sbin)]) + sbin
        return bytes([0x30, len(result)]) + result
    
class PrivateKey:
    def __init__(self, secret):
        self.secret = secret
        self.point = secret * G
    def hex(self):
        return "{:x}".format(self.secret).zfill(64)
    def sign(self, z):
        k = self.deterministic_k(z)
        r = (k * G).x.num
        k_inv = pow(k, N - 2, N)
        s = (z + r * self.secret) * k_inv % N
        if s > N / 2:
            s = N - s
        return Signature(r, s)
    def deterministic_k(self, z):
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < N:
                return candidate
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()