---
title: "LIT CTF"
date: 2023-08-06T11:45:26-04:00
categories: [ctf, writeup]
tags:
math: true
cover:
    image: litctf_banner2.png
---

These writeups are for challenges I solved after the CTF. Some of these I have captured solutions from others' writeups for my reference. 

<!--more-->
### Solutions
#### Crypto/E(Z/C)LCG
We are given an Elliptic Curve cryptography based challenge source, that uses a 80-bit prime, randomized `a` and `b` parameters. Using the original generator of this curve, a linear congruential generator is created and the `[X,Y]` coordinates of two sequential points are given to us. The `X` coordinate of the third point is used to generate the key for encrypting the flag with AES-CBC. The IV and the encrypted flag are provided to us.  

```python
from random import SystemRandom
random = SystemRandom()

def fun_prime(n): # not as smooth as my brain but should be enough
    while True:
        ps = 16
        p = 1
        for i in range(n//ps):
            p *= random_prime(2^ps)
        p += 1
        if is_prime(p):
            return p
def gen(b):
    p = fun_prime(b)
    E = EllipticCurve(GF(p), [random.randint(1, 2^b), random.randint(1,2^b)])
    return E, p, E.order()

C, p, order = gen(80)
# woah thats an lcg
class lcg:
    def __init__(self, C: EllipticCurve):
        self.order = order
        self.a = random.randint(1, self.order)
        self.x = C.gens()[0]
        self.b = self.x * random.randint(1, self.order)
    def next(self):
        self.x = (self.a * self.x + self.b)
        return self.x

prng = lcg(C)
x0 = prng.next()
x1 = prng.next()
x0, y0 = x0.xy()
x1, y1 = x1.xy()
print(f"{x0 = }")
print(f"{y0 = }")
print(f"{x1 = }")
print(f"{y1 = }")
print(f"{p = }")

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.Padding import pad
from os import urandom
v = int(prng.next().xy()[0])
k = pad(l2b(v**2), 16)
iv = urandom(16)
cipher = AES.new(k, AES.MODE_CBC, iv=iv)
print(f"iv = '{iv.hex()}'")
f = open("flag.txt",'rb').read().strip()
enc = cipher.encrypt(pad(f,16))
print(f"enc = '{enc.hex()}'")
```
The solution approach would be: 
1. Given that `(X0, Y0)` and `(X1, Y1)` are points on the curve, determine the original parameters `a` and `b` of the Elliptic Curve, assuming that it is a Weierstrass equation of the form \\(y^2 = x^3 + ax + b\\).
1. Recreate the curve and recover the generator points using `C.gens()`
1. Using three consecutive values of the LCG, recreate the parameters of the LCG
1. Predict the next point and use it to recreate the AES key
1. Use the Key and IV to decrypt the encrypted flag.

The coded solution in `sagemath` is as follows:

```python
# Given x0, y0, x1, y1, p, iv, enc

C_a, C_b = attack(p, x0, y0, x1, y1)        # recover the parameters of the curve
E = EllipticCurve(GF(p), [C_a, C_b])        # recreate the curve using the original parameters

P0 = E.gens()[0]                # get the generator point
# convert the known points to sage format
P1 = E(x0, y0)
P2 = E(x1, y1)

print(f"{P0 =}\n{P1 =}\n{P2 =}")
# Given that P0, P1 and P2 are the consecutive points in a LCG sequence, 
# P1 = P0 * a + b and so on.
lcga = (P1 - P0).discrete_log(P2-P1)
lcgb = P1 - (P0 * lcga)

P3 = P2 * lcga + lcgb

v = int(P3.xy()[0])  # get the X value

import binascii
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.Padding import pad, unpad

iv = binascii.unhexlify(iv)
enc = binascii.unhexlify(enc)
k = pad(l2b(v**2), 16)          # Use the x value of the next point as the key
cipher = AES.new(k, AES.MODE_CBC, iv=iv)
print(f"{unpad(cipher.decrypt(enc), 16).decode()} ")

# LITCTF{Youre_telling_me_I_cant_just_throw_elliptic_curves_on_something_and_make_it_100x_secure?_:<}
```
$$
P_1 = P_0 * a_{lcg} + b_{lcg}     \\\
P_2 = P_1 * a_{lcg} + b_{lcg}   \\\
$$

$$
    {P_2 - P_1} = a_{lcg} * {P_1 - P_0} \\\
    \therefore a_{lcg} = {(P_1 - P_0)}\text{.discrete\\_log}({P_2 - P_1})
$$

$$
b_{lcg} = P_1 - P_0 * a_{lcg}
$$

I used the cryto utility function from https://github.com/jvdsn/crypto-attacks. The underlying logic for why this is the case is:

$$ 
y_1^2 = x_1^3 + ax_1 + b \mod p\\\ 
y_2^2 = x_2^3 + ax_2 + b \mod p
$$

$$
y_1^2 - y_2^2 =  x_1^3 - x_2^3 + a (x_1 - x_2) \mod p\\\
\therefore a = \frac {(y_1^2 - y_2^2) - (x_1^3 - x_2^3)} {(x_1 - x_2)}  \mod p
$$

```python
#from https://github.com/jvdsn/crypto-attacks
def attack(p, x1, y1, x2, y2):
    """
    Recovers the a and b parameters from an elliptic curve when two points are known.
    :param p: the prime of the curve base ring
    :param x1: the x coordinate of the first point
    :param y1: the y coordinate of the first point
    :param x2: the x coordinate of the second point
    :param y2: the y coordinate of the second point
    :return: a tuple containing the a and b parameters of the elliptic curve
    """
    a = pow(x1 - x2, -1, p) * (pow(y1, 2, p) - pow(y2, 2, p) - (pow(x1, 3, p) - pow(x2, 3, p))) % p
    b = (pow(y1, 2, p) - pow(x1, 3, p) - a * x1) % p
    return int(a), int(b)
```

#### LCG... Squared?

```python
# inferior rngs
from random import SystemRandom
random = SystemRandom()
from Crypto.Util.number import getPrime
p = getPrime(64)
class lcg1:
    def __init__(self, n=64):
        self.a = random.randint(1, 2**n)
        self.b = random.randint(1, 2**n)
        self.x = random.randint(1, 2**n)
        self.m = p
    def next(self):
        ret = self.x
        self.x = (self.a * self.x + self.b) % self.m
        return ret

class lcg2:
    def __init__(self, n=64):
        self.lcg = lcg1(n)
        self.x = random.randint(1, 2**n)
        self.b = random.randint(1, 2**n)
        self.m = p
    def next(self):
        self.x = (self.lcg.next() * self.x + self.b) % self.m
        return self.x

lcg = lcg2()
print(p)            # prints prime
for x in range(5):
    print(lcg.next())   # prints 5 consecutive LCG2 entries.

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.Padding import pad
from os import urandom
r = lcg.next()
k = pad(l2b(r**2), 16)
iv = urandom(16)
cipher = AES.new(k, AES.MODE_CBC, iv=iv)
print(iv.hex())     # prints IV
f = open("flag.txt",'rb').read().strip()
enc = cipher.encrypt(pad(f,16))
print(enc.hex())    # prints ciphertext
```





### Writeups and resources
* https://en.wikipedia.org/wiki/Elliptic_curve
* https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/
* https://crypto.stackexchange.com/questions/91989/large-prime-numbers-in-ecc-and-discrete-logarithm

### Challenges 
|Challenge|Category|Difficulty|Description
|----|----|----|----
|crypto/Climbing Snowdon|crypto|5|
|crypto/E(Z/C)LCG|crypto|3|
|crypto/Kirby's Recipe|crypto|5|
|crypto/LCG to the power of n!|crypto|7|
|crypto/LCG... Squared?|crypto|5|
|crypto/The Door to the Xord|crypto|6|
|crypto/Your Did It!|crypto|8|
|crypto/are YOU smarter than Joseph-Louis Lagrange????|crypto|10|
|crypto/cursed ciphers|crypto|4|
|crypto/icecream|crypto|3|
|crypto/leaderboard-service|crypto|6|
|crypto/polypoint|crypto|6|
|misc/Blank and Empty|misc|2|
|misc/HelloWorld|misc|1|
|misc/KirbBot has a secret...|misc|10|
|misc/So You Think You Can Talk|misc|5|
|misc/Survey|misc|1|
|misc/amogus|misc|1|
|misc/codetiger orz|misc|4|
|misc/discord and more|misc|0|
|misc/geoguessr|misc|3|
|misc/incredible|misc|2|
|misc/kevin|misc|1|
|misc/obligatory pyjail|misc|6|
|misc/rayzarrayz|misc|3|
|misc/the other obligatory pyjail|misc|5|
|misc/wow it's another pyjail|misc|10|
|pwn/File Reader?|pwn|3|
|pwn/My Pet Canary's Birthday Pie|pwn|2|
|pwn/SHA-SHA-Shell|pwn|4|
|pwn/cat|pwn|5|
|pwn/sprintf|pwn|6|
|pwn/stiller printf|pwn|7|
|pwn/susprintf|pwn|10|
|rev/budget-mc|rev|5|
|rev/ilovepython|rev|8|
|rev/iloveregex|rev|4|
|rev/obfuscation|rev|3|
|rev/rick|rev|1|
|rev/squish|rev|5|
|rev/whar|rev|7|
|web/EyangCH Fanfic Maker|web|7|
|web/My boss left|web|3|
|web/Ping Pong: Under Maintenance|web|5|
|web/Ping Pong|web|2.5|
|web/The Even More Most LIT Foundation|web|10|
|web/The Most LIT Foundation|web|6|
|web/amogsus-api|web|2.5|
|web/art-contest|web|7|
|web/fetch|web|4|
|web/license-inject|web|3|
|web/too much kirby|web|20|
|web/unsecure|web|2|