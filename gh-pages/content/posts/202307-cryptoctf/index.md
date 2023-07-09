---
title: "CryptoCTF"
date: 2023-07-08T03:47:48-04:00
categories: [ctf, writeup]
tags: [cryptoctf, diophantine, RSA]
math: true
cover:
    image: cryptoctf_banner.png
---

This is a challenging crypto-centric CTF organized by ASIS. 
<!--more-->

### Solved Challenges

#### Blue Office
`The Blue Office's ingenious cipher, meticulously crafted for the prestigious CCTF, became an impenetrable enigma that left even the most seasoned cryptanalysts baffled.`

```python
    def encrypt(s, msg):
        assert s <= 2**32
        c, d = 0, s
        enc, l = b'', len(msg)
        while c < l:
            d = reseed(d)
            enc += (msg[c] ^ ((d >> 16) & 0xff)).to_bytes(1, 'big')
            c += 1
        return enc
```
The following python script represents the solution.  We would bruteforce the `orig_seed` in the space of \\(2^{32}\\). We can ignore the red herring with the `gen_seed(seed_str)` function, which generates the starting seed from a secret string. 

```python
'''
known_bytes = [f3, 88, 37, 50, 42]  -- corresponds to b'CCTF{'
    43^b0 = f3  'C' 
    43^cb = 88  'C'
    54^63 = 37  'T'
    46^16 = 50  'F'
    7b^39 = 42  '{'
'''
hex_str = unhexlify(b'b0cb631639f8a5ab20ff7385926383f89a71bbc4ed2d57142e05f39d434fce')

# Bruteforce the seed and check for the first 5 characters to be  b'CCTF{'
def check_next_seed(orig_seed, cur_seed, index):
    marker_byte = (cur_seed >> 16) & 0xFF 
    if (marker_byte == known_bytes[index]): 
        next_seed = reseed(cur_seed)
        if (index <= 3):
            check_next_seed(orig_seed, next_seed, index+1)
        elif(index == 4):
            # We have found "CCTF{". So, stop recursion and decrypt the full flag
            flag=b''
            d = orig_seed
            for c in hex_str:
                flag += (c ^ ((d >> 16) & 0xff)).to_bytes(1, 'big')
                d = reseed(d)
            print(f"Seed found : {orig_seed:08x} {flag}")
```
#### Suction
`The easy suction cryptosystem is designed with a primary focus on simplicity and user-friendliness, employing streamlined algorithms that make encryption straightforward and accessible even for individuals without extensive technical knowledge.`

This is an RSA challenge with `N` and `e` obscured by hiding the last 8 bits of each. Since `p` and `q` are equally sized primes, we can deduce that `N` is odd and has only two equal sized factors. We can bruteforce `N` through 128 possible values to complete `N` and checking it for two equal-sized factors. 

```python
    for p,q in possible_n:          # check the 128 values for N to have only two equal sized factors
        n = p*q
        phi = (p-1)*(q-1)

        for e_ in possible_e:       # 28 prime values 
            if (GCD(e_, phi) == 1):
                d = inverse(e_, phi)
                for i in range(256):    # 256
                    pt = bytearray(long_to_bytes(pow((ENC<<8) + i, d, n)))
                    count +=1
                    if (pt.isascii()):      # cannot check for 'CCTF' as it is removed before encryption
                        print(pt)
```


#### TPSD
`Solving Diophantine equations is a notoriously challenging problem in number theory, and finding non-trivial integer solutions for certain equations is considered a major open problem in mathematics.`

In this challenge, we are asked to solve 20 levels of the diophantane equation \\(x^3 + y^3 + z^3 = 1\\). Common to all the 20 levels are the following conditions:
1. The values of `x`, `y` and `z` are integers. 
1. One of the values has to be a prime number. 
1. At each level, there are minimum and maximum values (expressed in terms of bit lengths of the absolute values of x, y and z). The minimum bit lengths become progressively longer at advanced levels. 

Luckily for us, this particular variant of the diophantane equation has been parameterized. The solution to the diophantane equation of the form \\(x^3 + y^3 + z^3 = 1\\) is given by \\( (9a^4)^3 + (3a - 9a^4)^3 + (1-9a^3)^3 = 1\\), for integer \\(a\\)

Looking at the three terms, we can easily see that only the third parameter can a prime number. Not knowing how long it would take to find a suitable value, I chose to pre-generate the triples for bit lengths upto 250. It so happened that the generation was very fast and if necessary, we could generate it on the fly. 


```python
import gmpy2
import math

start_bit_len=6
end_bit_len=200

with open("cube_sums.txt", 'w') as F:
    for bl in range(start_bit_len, end_bit_len,1):
        start_val = math.ceil(-1 * (2**bl)/9)
        i = start_val
        while(True):
            z = 1 - 9 * (i**3)
            if (gmpy2.is_prime(z)):
                x = 9 * (i ** 4)
                y = 3 * i - 9 * (i ** 4)
                F.write(f"{x},{y},{z} : {len(bin(abs(x))[2:]):3d} {len(bin(abs(y))[2:]):3d} {len(bin(abs(z))[2:]):3d}\n")
                print(f"Len:[{bl}?] [{len(bin(z))-2:4d}] {x},{y},{z}")
                break
            i -= 1
```
### After the CTF
There were a couple of other challenges that I could have solved if I had more time. So, I will catalog them here as I solve them for future reference, along with interesting solutions from other writeups.


### Resources
* https://ericrowland.github.io/papers/Known_families_of_integer_solutions_of_x%5E3+y%5E3+z%5E3=n.pdf
* https://www.ams.org/journals/mcom/2007-76-259/S0025-5718-07-01947-3/S0025-5718-07-01947-3.pdf
* https://gist.github.com/4yn/61af8672bed251e5366988e2efa6e658
* https://en.wikipedia.org/wiki/Sums_of_three_cubes


### List of challenges
|Category|Challenge|Description
|----|----|----
|Easy 😁|Blue Office|
|Easy 😁|Did it!|
|Easy 😁|Suction| RSA with obscured N and E
|Hard 😥|Big|
|Hard 😥|Byeween|
|Hard 😥|Marjan|
|Hard 😥|Shevid|
|Hard 😥|Vinefruit|
|Medium 🤔|ASIv1|
|Medium 🤔|Barak|
|Medium 🤔|Bertrand|
|Medium 🤔|Blobfish|
|Medium 🤔|Derik|
|Medium 🤔|Insights|
|Medium 🤔|Keymoted|
|Medium 🤔|Resuction|
|Medium 🤔|Risk|
|Medium 🤔|Roldy|
|Medium 🤔|TPSD| Sum of 3 cubes Diophantine equation
|Medium 🤔|Trex|
|Tough 🔥|ASIv2|
|Tough 🔥|Slowsum|
|Warm-up 🤑|Welcome!|