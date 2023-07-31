---
title: "Imaginary CTF 2023"
date: 2023-07-21T21:59:14-04:00
categories: [ctf, writeup]
tags: [rsa, 'reverse crc32']
cover:
    image: ictf_banner.png
---

Writeups for some of the crypto challenges from ImaginaryCTF.

<!--more-->

### Challenges
#### RSA

We are given a encrypted flag `flag.enc`, private key `private.pem` and public key `public.pem`


```bash
    % openssl rsa -in private.pem -text -noout  
    Private-Key: (1024 bit, 2 primes)
    modulus:
    ...
    ...

    % openssl pkeyutl -decrypt -in flag.enc -inkey private.pem 
    Public Key operation error
    007EB11801000000:error:0200009F:rsa routines:RSA_padding_check_PKCS1_type_2:pkcs decoding error:crypto/rsa/rsa_pk1.c:269:
    007EB11801000000:error:02000072:rsa routines:rsa_ossl_private_decrypt:padding check failed:crypto/rsa/rsa_ossl.c:499:


    % openssl pkeyutl -decrypt -in flag.enc -inkey private.pem -pkeyopt rsa_padding_mode:none
    ictf{keep_your_private_keys_private}%   
```

#### Signer

```python
    # Standard RSA stuff
    p, q = getPrime(1024), getPrime(1024)
    n = p*q
    e = 65537
    d = pow(e, -1, (p-1)*(q-1))

    PASSWORD = b"give me the flag!!!"

    # <snip>

    while True:
    print("1. Sign")
    print("2. Get flag")
    choice = int(input())

    if choice == 1:
        print("Enter message:")
        message = input().encode()
        # crc32 is secure and has no collisions, but just in case
        if message == PASSWORD or crc32(message) == crc32(PASSWORD):
        print("Stop this trickery!")
        exit()
        print("Signature:", pow(crc32(message), d, n))
    elif choice == 2:
        print("Enter the signature for the password:")
        s = int(input())
        if pow(s, e, n) == crc32(PASSWORD):
        print("You win! The flag is", open("flag.txt").read())
        exit()
        else:
        print("Wrong.")
        exit()

```

The challenge source shows that the challenge server is doing the following processing.

1. Establishes a standard RSA setup with two 1024-bit primes.
1. The source also establishes a password `b"give me the flag!!!"`
1. We are expected to provide an integer `s`, which, when encoded with the RSA parameters, would be equal to the CRC32 of the password. 
1. To assist in this endeavor, the challenge server will verify any value we give it, as long as it is not the password or share the CRC32 value with the password. This is a safe move because the funny comment in the source saying `crc32 is secure and has no collisions, but just in case`.  CRC32 is definitely not collision free and it is not secure to be tamper resistant.
1. Note that the operation under option #1 is the inverse of the signing operation, i.e \\(CRC_{string}^d \mod N\\) for any string we pass in.
1. The solution is rather simple. We need to supply \\(s\\) such that \\(s^e \mod N == CRC_{password} \\)
1. Let's factor the \\(CRC_{password}\\), such that \\(CRC_{password}  =  C_1  * C_2\\)
1. If we can determine two strings \\(T_1~and~T_2\\), such that their CRCs are deterministic and can be set to \\(C_1 and C_2\\) respectively.
1. Then if their corresponding signatures are \\(S_1 and S_2\\), then the desired signature of the password \\(s = S_1 * S_2\\) due to the multiplicative property of modulus.
1. There are a number of reverse CRC32 implementations on GitHub. I used https://github.com/theonlypwner/crc32

The steps used are : 

```ipython
    In [2]: PASSWORD = b"give me the flag!!!"
    In [3]: crc32(PASSWORD)
    Out[3]: 3542523789
    In [4]: assert 87619 * 40431 == crc32(PASSWORD)
    In [5]: print(87619 * 40431 == crc32(PASSWORD) )
    True
    In [6]: crc32(b'BeSqrm')
    Out[6]: 87619
    In [7]: crc32(b'ZJWWgU')
    Out[7]: 40431
```

```bash
% crc32.py reverse 87619
    4 bytes: {0xfc, 0xdb, 0x3c, 0xd3}
    verification checksum: 0x00015643 (OK)
    ...
    6 bytes: BeSqrm (OK)
    ...

% crc32.py reverse 40431
    4 bytes: {0xf8, 0x58, 0xe3, 0xc2}
    verification checksum: 0x00009def (OK)
    ...
    6 bytes: ZJWWgU (OK)
    ...
```

Now that we know that strings `BeSqrm` and `ZJWWgU` will produce CRC values, which when multiplied together gives the CRC value of the PASSWORD, we are ready to code the exploit. 

```python

PASSWORD = b"give me the flag!!!"
mP = crc32(PASSWORD)
# crc32.py reverse 87619      
# crc32.py reverse 40431
p1,p2 = b'BeSqrm', b'ZJWWgU'

mp1,mp2 = crc32(p1), crc32(p2)

# ensure that the CRC values are indeed factors of the CRC value of the PASSWORD
assert mp1 * mp2 == mP

print(f"Desired CRC: {mP} \n Factors: {mp1} * {mp2}")

s1 = 0
s2 = 0

with remote('signer.chal.imaginaryctf.org',  1337) as P:
    P.recvuntil(b'Get flag')
    P.sendline(b'1')
    P.recvuntil(b'Enter message:')
    P.sendline(p1)
    P.recvuntil(b'Signature: ')
    s1 = int(P.recvline().decode().strip())
    print(f"Received sig1: {s1}")

    P.recvuntil(b'Get flag')
    P.sendline(b'1')
    P.recvuntil(b'Enter message:')
    P.sendline(p2)
    P.recvuntil(b'Signature: ')
    s2 = int(P.recvline().decode().strip())
    print(f"Received sig2: {s2}")

    # Multiply the two signatures together
    s = s1 * s2 

    print(f"Will send: {s}")

    P.recvuntil(b'Get flag')
    P.sendline(b'2')
    P.recvuntil(b'for the password:')
    P.sendline(str(s).encode())
    P.interactive()

    # [*] Switching to interactive mode
    # You win! The flag is ictf{m4ybe_crc32_wasnt_that_secure_after_all_1ab93213}
```


### References
* https://github.com/maple3142/My-CTF-Challenges/tree/master/ImaginaryCTF