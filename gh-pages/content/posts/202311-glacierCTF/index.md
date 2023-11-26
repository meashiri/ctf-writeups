---
title: "Glacier CTF by LosFuzzys"
date: 2023-11-25T21:59:40-05:00
categories: [ctf, writeup]
tags: [RSA, DER, CloneHero]
math: true
cover:
    image: "gctf_banner.png"
---
This is a CTF contest hosted by LosFuzzys. The challenges were of good quality. I would rate them to be of intermediate to hard level. I played with the team `Weak But Leet` and we were placed 44th.

<!--more-->

### Intro
#### ARISAI
`I heard that RSA with multiple primes is more secure. My N is very large, so there should not be a problem.`

```python
PRIME_LENGTH = 24
NUM_PRIMES = 256

FLAG = b"gctf{redacted}"

N = < long number > 
e = 65537

for i in range(NUM_PRIMES):
    prime = getPrime(PRIME_LENGTH)
    N *= prime

ct = pow(bytes_to_long(FLAG), e, N)

print(f"{N=}")
print(f"{e=}")
print(f"{ct=}")
```
This is a case of a text-book RSA challenge, with the modulus that has multiple prime factors, than the typical two. In fact, we can see that `N` is a product of 256 24-bit primes.  The challenge here is to find the private exponent `d`. This article [^1] provides the roadmap to solve this challenge. 

[^1]: https://crypto.stackexchange.com/questions/74891/decrypting-multi-prime-rsa-with-e-n-and-factors-of-n-given

![](2023-11-26-10-15-31.png)

```python
from factordb.factordb import FactorDB
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long

# we are given n, e and ct
n = 
e = 
ct=

print(f"Bit length of N : {n.bit_length()}") # Bit length of N : 6030

f = FactorDB(n)
f.connect()
r = f.get_factor_list()

print(f"# of factors = {len(r)}")           # # of factors = 256

repeated_primes = []  # to keep track of non-distinct primes
phi = 1

for p in r:
    if (p in repeated_primes):  # we have seen the prime before
        phi *= p
    else: 
        phi *= (p-1)
        repeated_primes.append(p)   # add to list of primes


d = inverse(e, phi)
m = pow(ct, d, n)
print(long_to_bytes(m)) # b'gctf{maybe_I_should_have_used_bigger_primes}'
```

#### Los-ifier

### Crypto
#### Missing Bits
In this challenge, we are given a RSA private key in the DER format, but with the first 6 lines removed. Knowing that the private key is in the ASN.1 DER format, allows us to identify and extract the fields of the key. 

```bash
% base64 -d -i priv.key -o priv_key.bin     # convert partial RSA priv key to binary
```
The format of the complete RSA private key follows the following format in ASN.1 notation. 
```
RSAPrivateKey ::= SEQUENCE {
  version           Version,                        <--- MISSING
  modulus           INTEGER,  -- n                  <--- INCOMPLETE
  publicExponent    INTEGER,  -- e                  <--- EXTRACT (e)
  privateExponent   INTEGER,  -- d                  
  prime1            INTEGER,  -- p                  <--- EXTRACT (p)
  prime2            INTEGER,  -- q                  <--- EXTRACT (q)
  exponent1         INTEGER,  -- d mod (p-1)
  exponent2         INTEGER,  -- d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```
The first few lines removed from the base64 version of the private key has mangled the version and modulus fields. However, with the exponents and the private prime factors, we can recalculate all other values and decrypt the file.  Using this online diagram [^4] as a guide, we can identify the offset of `e`, `p` and `q`.

[^4]: https://www.cem.me/20141221-cert-binaries.html

![](2023-11-26-13-17-10.png)

Once we have those fields, the rest is textbook RSA decryption. 

```python
from pwn import *
from Crypto.Util.number import isPrime, bytes_to_long, long_to_bytes, inverse

# https://www.cem.me/20141221-cert-binaries.html

p = "e4188b37b163...cd340bcb32a21"  # copy prime factor P from binary RSA key
q = "f122e285b030...0facafcd8569e7" # copy prime factor Q from binary RSA key
e = 0x10001

p = int(p, 16)
q = int(q, 16)

print(isPrime(p))   # Confirm P is prime  : True
print(isPrime(q))   # Confirm Q is prime  : True

n = p * q
ct = open('ciphertext_message', 'rb').read()
phi = (p-1) * (q-1)
d = inverse(e, phi)

ct = bytes_to_long(ct)

print(long_to_bytes(pow(ct, d, n))) 
# b'Hey Bob this is Alice.\nI want to let you know that the Flag is gctf{7hi5_k3y_can_b3_r3c0ns7ruc7ed}'

print(f"{d:0x}")        # matches the private exponent in the partial RSA key
```

#### SLCG
#### Glacier Spirit

### Misc
#### IcyRiffs

In this challenge, we are given two sets of files for the [Clone Hero game](https://clonehero.net/). The files provided are: 
```
notes.chart     # Mapping of frets, events and flags
song.ini        # Metadata about the song, not relevant to the chall
song.ogg        # Music to be played as the background. Not relevant
```

In researching more about this format, I found a <cite> online simulator [^2]</cite> that can play the charts, which was very helpful to understand the format. I also found a <cite>easy to use parser on Github [^3]</cite> for the chart files. 

The solution consisted of two steps. First to analyze the `Invincible` file set to create a mapping of fret values to a character. The second step is to analyze the `Monsters Inc.` fileset to determine a subset of fret values and map them to a character, using the mapping created before. 

**PART 1**: Read the `notes.chart` under `Invincible` and create a dictionary of fret values to the character in the lyrics. 

```python
import chparse
# https://github.com/Kenny2github/chparse
chartfile = open('./Invincible/notes.chart')
chart = chparse.load(chartfile)

event_dict = {}
for l in chart.events:
    if ('lyric' in l.event):
        event_dict[l.time] = l.event.split()[1]


#  5 frets are bit mapped to create fretval
#  4  3  2  1  0
#  o  o  o  o  o
prevtime = 0
fretval = 0
lyric_dict = {}
for n in chart.instruments[chparse.EXPERT][chparse.GUITAR]:
    # print(f"{n.time = } {n.kind = } {n.fret = } {n.length = } {n.flags = }")
    if (prevtime == 0):
        fretval = 1 << n.fret
    elif (n.time == prevtime):
        fretval = fretval | (1 << n.fret)
    elif(n.time != prevtime):
        # new time marker
        print(f"{prevtime:5d} : {fretval:3d} : {event_dict[prevtime]}")
        lyric_dict[fretval] = event_dict[prevtime]
        fretval = 1 << n.fret

    prevtime = n.time

# the last letter
print(f"{prevtime:5d} : {fretval:3d} : {event_dict[prevtime]}")
lyric_dict[fretval] = event_dict[prevtime]
# {1:'b', 2:'c' ... }  Key = fretvalue,  Val = lyric character
# print(lyric_dict)
```
**PART 2**: Read the `notes.chart` under `Randy Newman - Monsters, Inc.` and identify the fret values at each unique time marker. If we have seen a `TAP` signal, map the fret value to the lyrics character and add it to the flag. 

```python
mchartfile = open('./Randy Newman - Monsters, Inc. (JoeyD)/notes.chart')
mchart = chparse.load(mchartfile)

flag = ""
prevtime = 0
fretval = 0
found_tap = False 
for n in mchart.instruments[chparse.EXPERT][chparse.GUITAR]:
    # print(f"==DEBUG== >> {n.time = } {n.kind = } {n.fret = } {n.length = } {n.flags = }  {flag}")
    if (prevtime == 0):
        fretval = 1 << n.fret
    elif (n.time == prevtime):
        fretval = fretval | (1 << n.fret)
    elif(n.time != prevtime):   # new time marker
        if (found_tap):         # if we have found the tap, add the current char to the flag
            flag += lyric_dict[fretval]
            print(f"{prevtime:5d} : {fretval:3d} : {lyric_dict[fretval]} |  {flag}")
            found_tap = False

        fretval = 1 << n.fret

    found_tap = chparse.TAP in n.flags  # if the current tick has a tap, add the next char to the flag
    prevtime = n.time
print(flag)         # gctf{through_th3_moun4!ns_4nd_snow}
```
Also, whoever thought of planting a fake steg clue in the album image, you are a sadist.
![](5793587.png)

[^2]: https://nb48.github.io/chart-hero/
[^3]: https://github.com/Kenny2github/chparse
### Challenges
{{< collapse "Expand to see the list of challenges" >}}
|Category|Challenge|Description
|----|----|----
crypto |Glacier Spirit|
crypto |Missing Bits|
crypto |SLCG|
crypto |Shuffled AES|
crypto |Walking to the Sea Side|
intro |ARISAI|
intro |Los-ifier|
intro |My first Website|
intro |Skilift|
intro |Welcome challenge|
misc |Avatar|
misc |Glacier Military Daemon|
misc |IcyRiffs|
misc |Silent Snake|
pwn |35 Shades of Wasm|
pwn |FunChannel|
pwn |Glacier Rating|
pwn |Secure Password Storage|
pwn |Write Byte Where|
pwn |flipper|
rev |Password recovery|
rev |RPGO|
rev |SOP|
smartcontract |ChairLift|
smartcontract |GlacierCoin|
smartcontract |GlacierVault|
smartcontract |The Council of Apes|
web |Glacier Exchange|
web |Peak|
web |WhereIsTheScope|
{{< /collapse >}}