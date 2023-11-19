---
title: "Intigriti 1337Up CTF"
date: 2023-11-18T20:34:39-05:00
categories: [ctf, writeup]
tags: [rsa, knapsack, LLL]
math: true
cover:
    image: banner.png
---
A CTF organized by Intigriti. It had some interesting challenges. I mainly attempted the crypto category. 
<!--more-->
### Crypto

#### Really Secure Apparently
`Apparently this encryption is "really secure" and I don't need to worry about sharing the ciphertext, or even these values..`

```python
from factordb.factordb import FactorDB
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long

# Apparently this encryption is "really secure" and I don't need to worry about sharing the ciphertext, or even these values..
n = 68906103733948363685174487156486837...369599965441075497085384181772038720949 
e = 98161001623245946455371459972270637...65382600388541381732534018133370862587

print(f"Bit length of N : {n.bit_length()}")

f = FactorDB(n)
f.connect()
r = f.get_factor_list()

if (len(r) != 2):
    print(f"{r} .. does not have exactly two factors")
    raise Exception("Factor count not 2")
p,q = r
print(f"{p = }\n{q = }")

phi = (p-1)*(q-1)
d = inverse(e, phi)

ct = open('ciphertext', 'rb').read()
c = bytes_to_long(ct)
m = pow(c, d, n)
print(long_to_bytes(m))     

# ..... \xaeqqH\xd6\xfe\x00 Well done! Here is your flag: INTIGRITI{0r_n07_50_53cur3_m4yb3}
```
#### Keyless
`My friend made a new encryption algorithm. Apparently it's so advanced, you don't even need a key!`

```python
#  provided encrypt() function
def encrypt(message):
    encrypted_message = ""
    for char in message:
        a = (ord(char) * 2) + 10
        b = (a ^ 42) + 5
        c = (b * 3) - 7
        encrypted_char = c ^ 23
        encrypted_message += chr(encrypted_char)
    return encrypted_message

ct = open('flag.txt.enc', 'r').read()

flag = ''
for ch in ct:
    c = ord(ch) ^ 23
    b = (c + 7 ) // 3
    a = (b - 5) ^ 42
    fc = (a - 10) // 2
    flag += chr(fc)

print(flag)     # INTIGRITI{m4yb3_4_k3y_w0uld_b3_b3773r_4f73r_4ll}
```

#### 1-10
`One equation, ten unknowns?`

This is a variant of the knapsack problem. So, I attempted to solve it using LLL, which luckily yielded the solution. 

Here is the solution using Sagemath. 

```python
# given values
cs = [...]
s = ...

n = len(cs)     # 10
M = Matrix(ZZ, n+1, n+1)    # Create a 11 x 11 matrix

for i in range(n+1):
    M[i, i] = 1
    if (i == n):
        M[i, n] = -s
    else:
        M[i, n] = cs[i]

L = M.LLL()

if (L[0,n] == 0):       # indicates a potential solution
    flag = ""
    for i in range(n):
        flag += chr(L[0,i] % 1000)  # get the character value

print(f"INTIGRITI{{{flag}}}")       # INTIGRITI{3a8a32c7f6}
```

### Warmups

#### Over The Wire 1

#### Over The Wire 2

### Misc


### Challenges
{{< collapse "Expand to see the list of challenges" >}}
|Category|Challenge|Description
|----|----|----
|Crypto|1-10|
|Crypto|Keyless|
|Crypto|Not So Smooth|
|Crypto|Really Secure Apparently|
|Crypto|Share It (part 1)|
|Crypto|Share it (part 2)|
|Game Hacking|Dark Secrets|
|Game Hacking|Escape|
|Game Hacking|Smiley Maze|
|Misc|Leeky Comics|
|Misc|PyJail|
|Misc|Triage Bot|
|Misc|ZeChat|
|Mobile|Fetchzer|
|Mobile|MemDump|
|OSINT|Photographs|
|Pwn|Floor Mat Store|
|Pwn|Hidden|
|Pwn|Maltigriti|
|Pwn|Over The Edge|
|Pwn|Reading in the Dark|
|Pwn|Retro-as-a-Service|
|Pwn|Seahorse Hide 'n' Seek|
|Pwn|Stack Up|
|Reversing|Anonymous|
|Reversing|Can We Fix It|
|Reversing|Crack Me If You Can|
|Reversing|FlagChecker|
|Reversing|Impossible Mission|
|Reversing|Lunar Unraveling Adventure|
|Reversing|Obfuscation|
|Reversing|Sad Power|
|Reversing|Virtual RAM|
|Reversing|imPACKful|
|Warmup|Discord|
|Warmup|Encoding|
|Warmup|Flag Extraction|
|Warmup|Over the Wire (part 1)|
|Warmup|Over the Wire (part 2)|
|Warmup|Reddit|
|Warmup|Try Hack Me|
|Warmup|Twitter|
|Web|Bug Bank|
|Web|Bug Report Repo|
|Web|CTFC|
|Web|E-Corp|
|Web|My Music|
|Web|OWASP|
|Web|Pizza Time|
|Web|Smarty Pants|
{{< /collapse >}}