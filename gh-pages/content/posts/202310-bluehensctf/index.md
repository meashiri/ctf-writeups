---
title: "UD Bluehens CTF"
date: 2023-10-30T19:38:39-04:00
categories: [ctf, writeup]
tags: [rsa]
math: true
cover:
    image: bluehensctf_banner.png
---

CTF from University of Delaware.

<!--more-->
### CRYPTO, BABY
#### Greatest Hits 1/4
`Start of a 4 part journey covering favorite basics`

```
https://gist.github.com/AndyNovo/5ef52bd5de7a210ff3390fe424297704
-> Binary string 
-> Base 32 
-> Base 64 
-> Base 62 
-> https://gist.github.com/AndyNovo/cd42f0f6daae3ef9c9a598a79fe3b877
-> Flag : UDCTF{D34r_Cyb3r_Ch3f_Th4nks_f0r_everyth1ng}
```
#### Greatest Hits 2/4
```python
from Crypto.Util.number import *
p=getPrime(1024)
q=getPrime(1024)
n=p*q
e1=32
e2=94
msg=bytes_to_long("REDACTED")
assert(pow(msg,2) < n)
c1 = pow(msg, e1, n)
c2 = pow(msg, e2, n)
print(n)
print(e1)
print(e2)
print(c1)
print(c2)
# we are given n, e1, e2, c1, c2
```
This is a common modulus attack, with a twist. 

```python
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long
from math import gcd
from gmpy2 import isqrt

def egcd(a, b):
    if a == 0:
        return (0, 1, b)
    else:
        y, x, g = egcd(b % a, a)
        return (x - (b // a) * y, y, g)

# we are given n, e1, e2, c1, c2
print(gcd(e1, e2))  # 2
u, v, g = egcd(e1, e2)  

print(u, v, g)      # 3 -1 2
m_squared = (pow(c1, u, n) * pow(c2, v, n)) % n
m = isqrt(m_squared)
print(long_to_bytes(m)) # b'https://gist.github.com/AndyNovo/aaa4bf206eaaa26dc7ccdbf5254236e0'

# https://crypto.stackexchange.com/questions/78325/common-modulus-attack-with-not-coprime-exponents

Flag : UDCTF{l4rg3_int3ger_sqrt_w1th0ut_fl04ts}
```
#### Greatest Hits 3/4

```python
    flaglink="REDACTED"

    def xor(msg, key):
        o = ''
        for i in range(len(msg)):
            o += chr(ord(msg[i]) ^ ord(key[i % len(key)]))
        return o

    clue="https://gist.github.com/AndyNovo"
    import os
    key = os.urandom(len(clue))
    assert(flaglink.count(clue) > 0)

    print(xor(flaglink, key).encode('hex'))
    #98edbf5c8dd29e9bbc57d0e2990e4e692efb81c2318c69c626d7ea42f2efc70fece4ae5c89c7999fef1e8bac99021d7266bc9cde3cd97b9a2adaeb08dea1ca0582eaac13ced7dfdbad1194b1c60f5d372eeec29832ca20d12a85b545f9f69b1aaeb6ec4cd4
```
Obviously, the flag is not starting at the beginning. Instead, it is at an undetermined offset. So, we bruteforce the key. 

```python
from pwn import * 

def xor1(msg, key):
    o = ''
    for i in range(len(msg)):
        o += chr(ord(msg[i]) ^ ord(key[i % len(key)]))
    return o

clue="https://gist.github.com/AndyNovo"

def rotate(S, num_pos):
    l = len(S)
    rotate_num = num_pos % l
    return S[-rotate_num:] + S[:-rotate_num]

# ct is given 
c = unhex(ct)
c = c.decode('ISO-8859-1')
l = len(clue)

for i in range(len(c)-len(clue)):
    key = xor1(c[i:l+i], clue)
    key = rotate(key, i)
    decoded = xor1(c, key)
    if (all([c.isprintable() for c in decoded])):
        # print the decoded message if all the characters are printable
        print(l, len(key), '.'.join([hex(ord(x))[2:] for x in key]))
        print(f"[{i:03d}]|{decoded} ")
        # The last stage of the problem is at https://gist.github.com/AndyNovo/d2415028d31f572ff9ec03bf95fb3605 

# Flag is UDCTF{x0r_and_I_g0_w4y_back}
```

#### Greatest Hits 4/4

```python
#Python 2.7
flag="REDACTED"
import random
import time
print(time.time())
#1697043249.53
time.sleep(random.randint(0, 50))
random.seed(int(time.time()))
ct=""
for c in flag:
    ct += chr(random.randint(0,255) ^ ord(c))
print(ct.encode('hex'))
#a0469bbb0b3a4f06306739032244b0c5119ba66a0d3b5a2322acdd7070bf85690cdf8573212c1b927e0ba624
```

```python
ct_hex = "a0469bbb0b3a4f06306739032244b0c5119ba66a0d3b5a2322acdd7070bf85690cdf8573212c1b927e0ba624"
ct_b = [int(ct_hex[i:i+2], 16) for i in range(0, len(ct_hex), 2)]   #get the bytes
t = 1697043249.53
for i in range(55):         # for safety
    random.seed(int(t+i))
    pt = ''.join([chr(random.randint(0,255) ^ c) for c in ct_b])
    if (all([ord(c)>32 and ord(c)<128 for c in pt])):
        print(pt)           # UDCTF{4hh_m3m0r1es_th4t5_wh4t_1ts_4ll_about}
```

### Crypto, Baby

#### RSA School - 1st Grade
`First day of school!`

`Textbook (optional): https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-1/`

```python
from Crypto.Util.number import *
p=getPrime(512)
q=getPrime(512)
n=p*q
e=65537
msg=bytes_to_long(b'UDCTF{REDACTED}')
ct=pow(msg,e,n)
print(p)
print(n)
print(e)
print(ct)
```
We are given `p` and `n`. Easy to factor `n`

```python
    assert n%p == 0
    q = n//p
    phi = (p-1)*(q-1)
    d = inverse(e, phi)
    m = pow(c, d, n)
    print(long_to_bytes(m))     # b'UDCTF{y3a_b0i_b4by_RSA!}'
```
#### RSA School - 2nd Grade

`Ok a little tougher.`

`Textbook (optional): https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-1/`

We are given `n`, `e` and `c`. However, `n` is quite small and can be factored using FactorDB. 
```python
    from factordb.factordb import FactorDB
    from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long

    n=166045890368446099470756111654736772731460671003059151938763854196360081247044441029824134260263654537
    e=65537
    c = 141927379986409920845194703499941262988061316706433242289353776802375074525295688904215113445883589653
    print(f"Bit length of N : {n.bit_length()}")

    f = FactorDB(n)
    f.connect()
    r = f.get_factor_list()

    if (len(r) != 2):
        print(f"{r} .. does not have exactly two factors")
        raise Exception("Factor count not 2")
    p,q = r
    print(p,q)

    phi = (p-1)*(q-1)
    d = inverse(e, phi)
    m = pow(c, d, n)
    print(long_to_bytes(m))     # b'UDCTF{pr1m3_f4ct0r_the1f!}'
```

#### RSA School - 3rd Grade
`Hope you paid attention in math class`

`Textbook (optional): https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-1/`

```python
    from Crypto.Util.number import *
    p=getPrime(512)
    q=getPrime(512)
    n=p*q
    e1=71
    e2=101
    msg=bytes_to_long(b'UDCTF{REDACTED}')
    c1 = pow(msg, e1, n)
    c2 = pow(msg, e2, n)
    print(n)
    print(e1)
    print(e2)
    print(c1)
    print(c2)
```
The same message is encrypted with two distinct exponents, but with the same modulus. So, a common modulus attack is used. 

```python
    def egcd(a, b):
        if a == 0:
            return (0, 1, b)
        else:
            y, x, g = egcd(b % a, a)
            return (x - (b // a) * y, y, g)
            
    print(f"{gcd(e1,e2)=}") # must be co-prime

    u, v, g = egcd(e1, e2)
    # check
    assert u*e1 + v*e2 == 1   # definition of EGCD

    print(f"{gcd(c1,n)=}")
    print(f"{gcd(c2,n)=}")

    m = (pow(c1, u, n) * pow(c2, v, n)) % n

    print(long_to_bytes(m))     # b'UDCTF{3uc1id_th4_60at}'
```
#### RSA School - 4th Grade
`Getting tired of school yet?`

```python
    from Crypto.Util.number import *
    e=65537
    your_e = getPrime(20)
    msg=bytes_to_long(b'UDCTF{REDACTED}')
    p=getPrime(512)
    q=getPrime(512)
    n=p*q
    assert(msg < n)
    ct=pow(msg, e, n)
    your_d = inverse(your_e, (p-1)*(q-1))
    print(your_e)
    print(your_d)
    print(n)
    print(e)
    print(ct)
```
In this case, we are given a pair of `e1` and `d1`, that were generated with the same totient function. Hence we can determine the totient function and decrypt the ciphertext using the original `e`. 

$$
d_1 = inverse(e_1, \phi) \\\
where, \phi = (p-1)*(q-1)\\\
e_1 * d_1 \equiv 1 \mod \phi\\\
\phi \equiv (e_1 * d_1) - 1\\\
d = inverse(e, \phi)\\\
pt = pow(c, d, n)
$$
```python
    phi = e1*d1 - 1

    d = inverse(e, phi)
    m = pow(c, d, n)
    print(long_to_bytes(m))
```
#### RSA School - 5th Grade

```python
from Crypto.Util.number import *
from gmpy2 import iroot 
# we are given n, e and c

croot, found = iroot(c, e)
if(found):
    print(long_to_bytes(croot))     # b'UDCTF{0k_m4yb3_d0nt_u5e_e_3qu4l5_3}'
```
#### RSA School - 6th Grade

```python
    from Crypto.Util.number import *
    msg=b'UDCTF{REDACTED}'
    pt=bytes_to_long(msg)
    p1=getPrime(512)
    q1=getPrime(512)
    N1=p1*q1
    e=3
    ct1=pow(pt,e,N1)
    p2=getPrime(512)
    q2=getPrime(512)
    N2=p2*q2
    ct2=pow(pt,e,N2)
    p3=getPrime(512)
    q3=getPrime(512)
    N3=p3*q3
    ct3=pow(pt,e,N3)
    # we are given N1, N2, N3, e, ct1, ct2, ct3
```
In this case, the same plaintext is encrypted using the same small exponent. This can be solved by `Hastad's broadcast attack`


#### RSA School - 7th Grade

#### RSA School - 8th Grade






### Challenges
{{< collapse "Expand to see the list of challenges" >}}
|Category|Challenge|Description
|----|----|----

{{< /collapse >}}
