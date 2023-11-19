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

```bash
% tshark -r otw_pt1.pcapng -Y ftp
  391 12.744331723 192.168.16.213 → 192.168.16.131 FTP 94 Response: 220 pyftpdlib 1.5.9 ready.
  393 15.196182853 192.168.16.131 → 192.168.16.213 FTP 76 Request: USER cat
  395 15.196741120 192.168.16.213 → 192.168.16.131 FTP 99 Response: 331 Username ok, send password.
 1880 29.104247242 192.168.16.131 → 192.168.16.213 FTP 99 Request: PASS 5up3r_53cur3_p455w0rd_2022
 1881 29.104830281 192.168.16.213 → 192.168.16.131 FTP 89 Response: 230 Login successful.
 1883 29.104963402 192.168.16.131 → 192.168.16.213 FTP 72 Request: SYST
 1884 29.105391488 192.168.16.213 → 192.168.16.131 FTP 85 Response: 215 UNIX Type: L8
 1886 31.382247948 192.168.16.131 → 192.168.16.213 FTP 94 Request: PORT 192,168,16,131,179,47
 1890 31.383328861 192.168.16.213 → 192.168.16.131 FTP 107 Response: 200 Active data connection established.
 1892 31.383468068 192.168.16.131 → 192.168.16.213 FTP 72 Request: LIST
 1893 31.384060881 192.168.16.213 → 192.168.16.131 FTP 120 Response: 125 Data connection already open. Transfer starting.
 1897 31.384532055 192.168.16.213 → 192.168.16.131 FTP 90 Response: 226 Transfer complete.
 1920 40.286258848 192.168.16.131 → 192.168.16.213 FTP 74 Request: TYPE I
 1921 40.286895128 192.168.16.213 → 192.168.16.131 FTP 92 Response: 200 Type set to: Binary.
 1922 40.287052904 192.168.16.131 → 192.168.16.213 FTP 95 Request: PORT 192,168,16,131,203,181
 1926 40.287994097 192.168.16.213 → 192.168.16.131 FTP 107 Response: 200 Active data connection established.
 1927 40.288122906 192.168.16.131 → 192.168.16.213 FTP 81 Request: RETR flag.zip
 1928 40.288639205 192.168.16.213 → 192.168.16.131 FTP 120 Response: 125 Data connection already open. Transfer starting.
 1930 40.288815994 192.168.16.213 → 192.168.16.131 FTP 90 Response: 226 Transfer complete.
 2827 69.110963242 192.168.16.131 → 192.168.16.213 FTP 94 Request: PORT 192,168,16,131,132,11
 2831 69.111993482 192.168.16.213 → 192.168.16.131 FTP 107 Response: 200 Active data connection established.
 2832 69.112088552 192.168.16.131 → 192.168.16.213 FTP 85 Request: RETR reminder.txt
 2833 69.112560314 192.168.16.213 → 192.168.16.131 FTP 120 Response: 125 Data connection already open. Transfer starting.
 2835 69.112995479 192.168.16.213 → 192.168.16.131 FTP 90 Response: 226 Transfer complete.
 3122 86.464355501 192.168.16.131 → 192.168.16.213 FTP 95 Request: PORT 192,168,16,131,162,139
 3126 86.465531985 192.168.16.213 → 192.168.16.131 FTP 107 Response: 200 Active data connection established.
 3127 86.465625183 192.168.16.131 → 192.168.16.213 FTP 82 Request: RETR README.md
 3128 86.466159467 192.168.16.213 → 192.168.16.131 FTP 120 Response: 125 Data connection already open. Transfer starting.
 3132 86.466378449 192.168.16.213 → 192.168.16.131 FTP 90 Response: 226 Transfer complete.
 3180 112.467181791 192.168.16.131 → 192.168.16.213 FTP 72 Request: QUIT
 3181 112.467823434 192.168.16.213 → 192.168.16.131 FTP 80 Response: 221 Goodbye.
```

Frame # 2834 contains the instructions to get the flag
```bash
% tshark -r otw_pt1.pcapng -Y "frame.number == 2834"  -Tfields -e data | xxd -p -r    
Hi cat,

This flag is really important so I had to encrypt it in case it falls into the wrong hands.

You already know the FTP password.. Just use the same here, but update it accordingly ;)
```
Frame # 1929 provides the content of the `flag.zip` file, which can be unzipped using the FTP password (from frame #1880), after updating the year to 2023.

```bash
% tshark -r otw_pt1.pcapng -Y "frame.number == 1929"  -Tfields -e data | xxd -p -r > flag.txt

% unzip -P 5up3r_53cur3_p455w0rd_2022 -c flag.zip
Archive:  flag.zip
   skipping: flag.txt                incorrect password

% unzip -P 5up3r_53cur3_p455w0rd_2023 -c flag.zip
Archive:  flag.zip
 extracting: flag.txt                
INTIGRITI{1f_0nly_7h3r3_w45_4_53cur3_FTP}
```
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