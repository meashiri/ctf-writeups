---
title: "TCP1P CTF"
date: 2023-10-14T17:30:44-04:00
categories: [ctf, writeup]
tags:
math: true
cover:
    image: "tcp1p_banner.png"
---

This CTF was organized by TCP1P, a CTF team/community from Indonesia. 

<!--more-->
#### Final Consensus
The key part of the challenge server is: 
```python
def generateKey():
	global a, b
	a = (str(random.randint(0, 999999)).zfill(6)*4)[:16].encode()
	b = (str(random.randint(0, 999999)).zfill(6)*4)[:16].encode()


def encrypt(plaintext, a, b):
	cipher = AES.new(a, mode=AES.MODE_ECB)  
	ct = cipher.encrypt(pad(plaintext, 16)) # The first stage of the encryption
	cipher = AES.new(b, mode=AES.MODE_ECB)  
	ct = cipher.encrypt(ct)                 # The second stage
	return ct.hex()

def main():
	generateKey()
	print("Alice: My message", encrypt(FLAG, a, b))
	print("Alice: Now give me yours!")
	plain = input(">> ")
	print("Steve: ", encrypt(plain.encode(), a, b))
	print("Alice: Agree.")
```

$$ 
    \text{plaintext} \to \overbrace{AES~ECB~Encrypt}^{\text{key:=[0..999999]}} \to \overbrace{AES~ECB~Encrypt}^{\text{key:=[0..999999]}} \to \text{ciphertext (provided)} 
$$

The approach for the solution is to create a dictionary for every possible key value for each stage.
1. Pick a plaintext (say `abcdefgh`) and submit it to the server and capture resulting ciphertext.
1. Also, capture the ciphertext for the flag. 
1. These two encryptions use two AES-CBC ciphers with the key material that is generated using a `rand()` function.
1. For the first stage, we provide a known plaintext and capture the output.
1. The dictionary is `cipher text -> key material`
1. For the second stage, we come from the opposite direction and bruteforce the key material for decrypting the ciphertext that was provided by the server. 
1. The dictionary is `decryption output -> key material`
1. Now, find the intersection of the keys for the two dictionaries. This will identify the case where `encryption(plaintext) = decryption(server ciphertext)`.  The values corresponding the matching keys in each dictionary will give the key materials for each stage.
1. Decrypt the given ciphertext using the two key material to get the flag.

$$
    \text{plaintext} \to \overbrace{AES~ECB~Encrypt}^{\text{key:=[0..999999]}} \to \overbrace{K:output\brace V:key}^{\text{dictionary}}
    \newline
    \text{ciphertext (provided)} \to \overbrace{AES~ECB~Decrypt}^{\text{key:=[0..999999]}} \to \overbrace{K:output\brace V:key}^{\text{dictionary}} 
$$

The complete solution is 
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwn import enhex, unhex

enc_flag = <snip>
known_text = pad(b'abcdefgh', 16)
known_ciphertext = bytes.fromhex('5888af33746bd586e535f1cd5f9d876b')

# brute-force all encryptions
encryption_table = {}           # key : value -> encryption result : key

for a in range(999999):
    key = (str(a).zfill(6)*4)[:16].encode()
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_custom = cipher.encrypt(known_text)
    encryption_table[encrypted_custom] = key
    
# brute all decryptions
decryption_table = {}           # key : value -> decryption result : key

for b in range(999999):
    key = (str(b).zfill(6)*4)[:16].encode()
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_custom = cipher.decrypt(known_ciphertext)
    decryption_table[decrypted_custom] = key

# find the intersection between the keys of decryption_table and encryption_table
# if there is an intersection, we can cross-reference the AES key we used
encryption_table_set = set(encryption_table.keys())
decryption_table_set = set(decryption_table.keys())

intersection = encryption_table_set.intersection(decryption_table_set).pop()

encryption_key = encryption_table[intersection]     # set the encryption key (first stage)
decryption_key = decryption_table[intersection]     # set the decryption key (second stage)

print(f"Found keys: {encryption_key}  {decryption_key}")

cipher1 = AES.new(encryption_key, AES.MODE_ECB)
cipher2 = AES.new(decryption_key, AES.MODE_ECB)

# now decrypt flag_enc twice in the reverse order
flag = cipher2.decrypt(enc_flag)
flag = cipher1.decrypt(flag).decode().strip()

print(flag)
```
#### One Pad Time 



#### Cherry Leak


#### zipzipzip
```bash
#!/bin/bash

for i in `seq 25000 1`
do
  ls zip-$i.zip
  pass=$(cat password.txt | tr -d '\r\n')
  rm password.txt
  unzip -P $pass -x zip-$i.zip  
  rm zip-$i.zip  
done
```

```bash
zip-25000.zip
Archive:  zip-25000.zip
 extracting: zip-24999.zip           
 extracting: password.txt            
zip-24999.zip
Archive:  zip-24999.zip
 extracting: zip-24998.zip           
 extracting: password.txt  
...
...
zip-1.zip
Archive:  zip-1.zip
 extracting: flag.txt                
...

./doloop.sh  2207.15s user 508.09s system 90% cpu 50:01.02 total

% cat flag.txt
TCP1P{1_TH1NK_U_G00D_4T_SCR1PT1N9_botanbell_1s_h3r3^_^}
```

### Challenges
{{< collapse "Expand to see the list of challenges" >}}
|Category|Challenge|Description
|----|----|----
Blockchain |Invitation|
Blockchain |Location|
Blockchain |VIP|
Blockchain |Venue|
Cryptography |Cherry Leak|
Cryptography |Eclairs|
Cryptography |Final Consensus|
Cryptography |Jack's Worst Trials|
Cryptography |One Pad Time|
Cryptography |Open the Noor|
Cryptography |Shiftgner|
Cryptography |Spider Shambles|
Forensic |Browser|
Forensic |Compromised|
Forensic |Ez PDF|
Forensic |Hacked|
Forensic |Reminiscence|
Forensic |brokenimg|
Forensic |hide and split|
Forensic |scrambled egg|
Misc |Another Discord|
Misc |Cat Kompani|
Misc |Certificate|
Misc |Feedback|
Misc |Guess My Number|
Misc |Landbox|
Misc |Nuclei|
Misc |PyMagic|
Misc |Sanity Check|
Misc |vampire|
Misc |zipzipzipzip|
Mobile |Imagery|
Mobile |Intention|
Mobile |Internals|
Mobile |Netsight|
Mobile |OTA|
PWN |Bluffer Overflow|
PWN |Game Changer|
PWN |NakiriAyame|
PWN |babyheap|
PWN |digital circuit|
PWN |message|
PWN |tickery|
PWN |unsafe safe|
PWN |💀|
Reverse Engineering |Debug Me|
Reverse Engineering |ELF Cracker|
Reverse Engineering |IOP|
Reverse Engineering |Lock the Lock|
Reverse Engineering |NoJS|
Reverse Engineering |Subject Encallment|
Reverse Engineering |Take some Byte|
Reverse Engineering |VA|
Web |A simple website|
Web |Bypassssss|
Web |Calculator|
Web |Latex|
Web |PDFIFY|
Web |Un Secure|
Web |fetcher|
Web |love card|
{{< /collapse >}}