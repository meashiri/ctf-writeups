---
title: "Buckeye CTF 2023"
date: 2023-09-29T20:36:22-04:00
categories: [ctf, writeup]
tags:
math: true
cover:
    image: buckeyectf.png
---

BuckeyeCTF is jeopardy-style CTF hosted by the Cybersecurity Club at The Ohio State University.

<!--more-->

#### My First Hash
`Here's your flag: 8f163b472e2164f66a5cd751098783f9 Psyc! Its encrypted. You think I'd give it to you that easily? Definitely don't look at my code tho -><- (when you find the flag, put it in bctf{} format)`

```python
str = hashlib.md5(str.encode())
```
Using a MD5 [reverse lookup site](https://md5.gromweb.com/?md5=8f163b472e2164f66a5cd751098783f9) gives us the string `orchestra`, which would yield the given hash. Hence the flag is `bctf{orchestra}`

```bash
% echo -n "orchestra" | md5 
8f163b472e2164f66a5cd751098783f9
```

#### Real Smooth
`I know you're not supposed to leave passwords in plain text so I encrypted them. The flag is in the format btcf, not bctf due to a typo.`

We are given a text file that consists of 11,430 passwords that are encoded with the `ChaCha20` stream cipher scheme. However, we can see that the `key` and `nonce` are reused for encoding, which means that every one of the passwords is XORed with the same random material.  We also can see that each password is padded on the right with spaces until it reaches the length of 18 characters. 

```python
    def main():
        lines = open("passwords.txt", "rb").readlines()
        key = get_random_bytes(32)
        nonce = get_random_bytes(8)
        lines = [x.ljust(18) for x in lines]
        lines = [encrypt(key, nonce, x) for x in lines]
        open("database.txt", "wb").writelines(lines)
```

First, we do some optimization as we notice that several of the entries in the database are duplicates. So, we need to keep only the unique values. Also, we can see that the right half (actually 22 hex characters) are the same for a large number of entries. This seems to indicate that these are encoded values of the spaces that are used to pad a password that is shorter than 18 characters. 

```bash
# we only need to keep 1298 unique entries out of 11,430 entries in the database
% sort database.txt| uniq  | wc
    1298    1298   48026

# search and catalog the last 22 hex characters and see that nearly half of them share the same values.
% cut -c 15-  database.txt | sort | uniq -c | sort -r -n
4844 24f2dc11e8510fc249ad48         <=== this should be all spaces
2975 0ef2dc11e8510fc249ad48
 297 61d8dc11e8510fc249ad48
```

```python
from pwn import *

'''
# store unique values in a db_uniq.txt file. 
% sort database.txt| uniq > db_uniq.txt
 
keys = [167, 78, 245, 199, 198, 76, 2, 4, 210, 252, 49, 200, 113, 47, 226, 105, 141, 104]
'''

def guess_character(hex_str, keypos):
    print(keys)
    print(*[hex(x) for x in hex_str])
    pos, char = input("Pos:Char ?").strip().split(":")
    position = int(pos)
    keys[position] = x[position] ^ ord(char)
    keypos -= 1
    return keypos

hex_lines = []
spaces_CT = unhex('24f2dc11e8510fc249ad48')  # 11 bytes representing encoded spaces

# keys = [167, 78, 245, 199, 198, 76, 2, 4, 210, 252, 49, 200, 113, 47, 226, 105, 141, 104]
# first_known_key = 0

keys = [b'\xFF']*18
first_known_key = 7 #we know PT and CT for 11 consecutive spaces

with open('db_uniq.txt', 'r') as F:
    for line in F:
        hex_lines.append(unhex(line.strip()))

print(f"Read {len(hex_lines)} lines from file")

# initialize the last 11 bytes of the key using space as the padding character. 
for i, x in enumerate(spaces_CT):
    keys[7+i] = x ^ ord(' ')

print(keys)

# work backwards by guessing the next character of any password that is easy to guess. 
# I used a password that was all sevens.
while (first_known_key > 0):
    print(f"First known key position : {first_known_key}")
    for x in hex_lines:
        print(xor(x[first_known_key:], keys[first_known_key:]))
        cmd = input()
        if (cmd.strip().lower() == 'g'):
            first_known_key = guess_character(x, first_known_key)
            break

# ok ... all keys are known ... dump the passwords
print(f"Keys: {keys}")

for x in hex_lines:
    passwd = xor(x, keys)
    if (b'btcf' in passwd or b'}' in passwd):
        print(passwd)           # btcf{w3_d0_4_l1773_kn0wn_pl41n73x7}

# b'3_kn0wn_pl41n73x7}'
# b'btcf{w3_d0_4_l177l'
```

#### Needle in the Wifi Stack

We are given a network capture file. The protocol statistics show that it contains about 100 thousand frames of WLAN SSID broadcasts.

```bash
% tshark -r frames.pcap -z io,phs
===================================================================
Protocol Hierarchy Statistics
Filter: 

radiotap                                 frames:101000 bytes:11316000
  wlan_radio                             frames:101000 bytes:11316000
    wlan                                 frames:101000 bytes:11316000
      wlan.mgt                           frames:101000 bytes:11316000
===================================================================
```
The SSID field of frame seems to contain a base64 string. So, the conjecture is that the flag is hidden in one of the base64 SSID strings.  The following bash pipeline automates searching for this needle in the haystack. 

```bash
% tshark -r frames.pcap -T fields -e wlan.ssid | xxd -p -r | base64 -d | grep bctf
bctf{tw0_po1nt_4_g33_c0ng3s7i0n}
bctf{tw0_po1nt_4_g33_c0ng3s7i0n}
...
```

#### Pong

We are just given an ip address and nothing more. Taking a clue from the title of the challenge, we ping the server, which produces an interesting error message.

```bash
% ping 18.191.205.48        
PING 18.191.205.48 (18.191.205.48): 56 data bytes
128 bytes from 18.191.205.48: icmp_seq=0 ttl=41 time=37.165 ms
wrong total length 148 instead of 84
128 bytes from 18.191.205.48: icmp_seq=1 ttl=41 time=37.589 ms
wrong total length 148 instead of 84
```
The `wrong total length` message seems to indicate that the response ICMP packet contains 64 bytes more than expected.  So, we set out to capture the responses. 
```bash
shell 1% sudo tcpdump -c 10 -vvv -XX -i any icmp 
12:38:10.112932 IP (tos 0x0, ttl 41, id 42760, offset 0, flags [none], proto ICMP (1), length 148)
    ec2-18-191-205-48.us-east-2.compute.amazonaws.com > localhost : ICMP echo reply, id 37292, seq 0, length 128
	0x0000:  9c00 0000 0100 0000 0100 0000 656e 3000  ............en0.
	0x0010:  0000 0000 0000 0000 0000 0000 0000 0000  ................
	0x0020:  0000 0000 0100 0000 0200 0000 0e00 0000  ................
	0x0030:  0000 0000 ffff ffff 0000 0000 0000 0000  ................
	0x0040:  0000 0000 0000 0000 0000 0000 0000 0000  ................
	0x0050:  0600 0000 ffff ffff 0000 0000 0000 0000  ................
	0x0060:  0000 0000 0000 0000 0000 0000 0000 0000  ................
	0x0070:  0000 0000 0000 0000 0000 0000 0000 0000  ................
	0x0080:  0000 0000 0000 0000 0000 0000 0000 0000  ................
	0x0090:  0000 0000 0000 0000 0000 0000 985a eb8f  .............Z..
	0x00a0:  0766 485d 3666 551c 0800 4500 0094 a708  .fH]6fU...E.....
	0x00b0:  0000 2901 47e8 12bf cd30 c0a8 01e1 0000  ..).G....0......
	0x00c0:  0e32 91ac 0000 651a f1f2 0001 1e80 0809  .2....e.........
	0x00d0:  0a0b 0c0d 0e0f 1011 1213 1415 1617 1819  ................
	0x00e0:  1a1b 1c1d 1e1f 2021 2223 2425 2627 2829  .......!"#$%&'()
	0x00f0:  2a2b 2c2d 2e2f 3031 3233 3435 3637 8950  *+,-./01234567.P          <--- PNG header
	0x0100:  4e47 0d0a 1a0a 0000 000d 4948 4452 0000  NG........IHDR..
	0x0110:  0258 0000 0258 0806 0000 00be 6698 dc00  .X...X......f...
	0x0120:  0000 c57a 5458 7452 6177 2070 726f 6669  ...zTXtRaw.profi
	0x0130:  6c65 2074 7970 6520 6578 6966 0000       le.type.exif..

shell 2% ping 18.191.205.48
```
Now, that we have established that we have 64 bytes of a PNG file appended to the ICMP response, we set out to capture all ICMP packets until we receive the `IEND` chunk or all of the PNG image. 

```bash
# To capture the ICMP responses to a PCAP file
% sudo tcpdump -vvv -XX -i any icmp -w pong.pcapng 
% tshark -f icmp -w pong.pcapng
% Wireshark -> Capture -> Start

# Analyze the PCAP file
% tshark -r pong.pcapng -T fields -e data -Y "ip.src == 18.191.205.48" | cut -c 97- | tr -d '\n' | xxd -p -r > pong.png
```

I had missed two ICMP response packets that were lost due to a timeout. I manually copied a frame from a similar chunk and used `pngfix` to fix the CRC. At the end of the day, the flag was visible in the bottom most section of the image. 

### Challenges
{{< collapse "Expand to see the list of challenges" >}}
|Category|Challenge|Description
|----|----|----
crypto |Electronical|
crypto |My First Hash|
crypto |Real Smooth|
crypto |Rivest-Shamir-Adleman|
crypto |Secret Code|
crypto |Turtle Tree|
crypto |coding 2|
crypto |coding|
misc |Birdwatching|
misc |Breaking Away|
misc |Just Hang, Man|
misc |Needle in the Wifi Stack|
misc |New Management|
misc |Ogrechat|
misc |Parkour|
misc |Smederij|
misc |aNyFT|
misc |nada|
misc |pong|
misc |replace-me|
misc |typscrip|
misc |weather|
pwn |Beginner Menu|
pwn |Bugsworld|
pwn |Frog Universe in C (FUC)|
pwn |Igpay Atinlay Natoriay 3000|
pwn |Starter Buffer|
pwn |chat_app|
pwn |flag-sharing|
pwn |lossless|
pwn |saas|
rev |8ball|
rev |Currency Converter|
rev |Emotional Damage|
rev |Skribl|
rev |Tape|
web |Font Review|
web |Ohio Instruments 84|
web |Sentiment|
web |Spa|
web |Stray|
web |Text Adventure API|
web |Triple D Columbus|
web |area51|
web |certs|
web |∞!|
{{< /collapse >}}