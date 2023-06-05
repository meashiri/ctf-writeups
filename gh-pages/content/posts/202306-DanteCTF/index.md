---
title: "DanteCTF by Born2Scan"
date: 2023-06-04T00:04:57-04:00
categories: [ctf, writeup, signals]
tags: [aprs, gqrx, knapsack]
cover:
    image: DanteCTF2.png
---
A very high quality Dante-themed CTF by the team Born2Scan. A very nice array of challenges, including some signals/radio ones. 
<!--more-->
### Challenges

#### Route Marks the Spot
`Aha, the little spirit says that the human became more ingenious! What a weird way to transmit something, though.`

We are given a PCAP file that contains captured network traffic.  As a first step in the analysis, we look at the protocol statistics:

```bash
$ tshark -r RoutesMarkTheSpot.pcapng -z io,phs
===================================================================
Protocol Hierarchy Statistics
Filter: 
eth                                      frames:5975 bytes:7861529
  ip                                     frames:5937 bytes:7852745
    tcp                                  frames:4943 bytes:7121215
      tls                                frames:1307 bytes:3687484
        tcp.segments                     frames:635 bytes:3135839
          tls                            frames:588 bytes:3017541
      http                               frames:33 bytes:21576
        ocsp                             frames:24 bytes:16675
        tcp.segments                     frames:2 bytes:3044
    udp                                  frames:994 bytes:731530
      dns                                frames:136 bytes:17775
      data                               frames:58 bytes:18063
      quic                               frames:800 bytes:695692
        quic                             frames:19 bytes:17994
          quic                           frames:4 bytes:5596
  ipv6                                   frames:34 bytes:8580
    data                                 frames:34 bytes:8580
  arp                                    frames:4 bytes:204
===================================================================
```
As with typical CTF challenges, TLS is usually out of scope. Hence, here we eliminate the 588 TLS frames and the 800 QUIC frames. This leaves the HTTP, IPv6 and the ARP traffic to examine. Cursory examination shows us that the HTTP traffic is not relevant to the challenge and there is nothing out of ordinary with the ARP packets. 

So, we examine one of the packets of the IPv6 traffic.  There are two fields that look interesting. The `ipv6.flow` field has a value that seems to be different in each packet. The `data` field seems to contain text data - which seems to indicate some kind of an encoding scheme (like base64).

```xml
    <field name="ipv6.flow" showname=".... 0000 0000 0000 0001 1110 = Flow Label: 0x0001e" size="3" pos="15" show="0x00001e" value="1E" unmaskedvalue="00001e"/>
    ...
    <field name="data" value="3479434b36463078457333766b30535259413374307354514b4a61467471426c3350334974466475664a746e4b4f496748785942574951474a6464474f3238474b4274596f774d6e74326935393532716e4b56597074583a6e3a777349645a566e3546325565645a4171776a5377694a44474668616d6a4d444d576b35747a4f4361664779327353655647646779317571746c484d51524c346c52417967716b616f39714959354c725135624863787144377a57394a31356f416f4f39616d4c6e54746e6d306c745135544a5a3662673754345674393430">
```

We will extract these two fields and store them in a file for further processing. 
```bash
    $ tshark -r RoutesMarkTheSpot.pcapng -T fields -e ipv6.flow -e data -Y ipv6 

    0x00001e	3479434b36463078457333766b30535259413374307354514b4  ...
    0x00001a	71376b53496774614f304169623467424e6b4754464e6b795a4  ...
    0x000018	6955447832495a413546365763626c6d35477333367247785a3  ...
    0x000000	6e69456d6f444f71396f524176706935665934556e644e316f6  ...
    0x00001b	7759534a4357306f644c4a65753074396255355373445765384  ...
    0x00001d	467362544b326d4b384a5274554c766344644e5256615030436  ...
    0x000021	4774336e324d44674165703957735a436e32473162744d69594  ...
    0x00000f	5879536c77626d4c736a46767a456872784d37395a4a636d397  ...
    0x000009	7a506345654b65775645586d6f6f41685859597765536979384  ...
    0x000005	71654e504e63387a617042544534344a7368595a4d7938356c5  ...
    0x00000c	67484b374a617937336c4465634a377855536c6673524352653  ...
    0x000011	753875547732454442577947597766656655667a46784e5a653  ...
    0x000006	7472784837684979656d6c7145785565443266684c395634427  ...
    0x000016	3066305a334555676569326d7836454a367a694245533270724  ...
    0x000008	656c67485769486357764165354849336e52383677305342744  ...
    0x00000e	546b644e596b72664b47613938536c51314d666c72527a5a556  ...
    0x000015	5834784b4e57396232794b32774b486f6a674c7375786637734  ...
    0x00000d	6d434878634748704542626f78587a7649726243724d55536f7  ...
    0x000004	3474316e77734a415431586a76324b424a34555479336f61644  ...
    0x000019	31657853396d75585a4964757355336941413278486f3358674  ...
    0x000020	6149517134637532534c306461466d7171367a77637776374c7  ...
    0x000001	36375a764d456f6c54744b6d54534f5a6c64737854477149366  ...
    0x00001f	72366f574365593772634d6467337a307771726f584248674c6  ...
    0x00000b	42544c3771456b4b614759347a674b765a7a6562764862776d4  ...
    0x000007	6348784833346f7650723150555a583874633773554e4455474  ...
    0x000013	316542306e4f79774f753841787666436f4d42756d333073517  ...
    0x000012	51567873316f63417a564e36574c693970724d56583364356e6  ...
    0x000017	6e62516c78466a3935596d34736b4c595a7179457a306c6c4d7  ...
    0x00000a	456c55666e5a6f54774f7a5864496e524f3670794e4d6849473  ...
    0x000002	4a52784159656958704a4a6b4c5365556261764773634e7a426  ...
    0x000010	56565079517659646239595870525679505574434a446338677  ...
    0x00001c	4c4e76546a79593772587a41646f48456770384f734173384c3  ...
    0x000014	6771586b7974464d4b525950733454617346534e4c587073564  ...
    0x000003	3868736b3334344a4e6f39527a596e545a554c336e733743563  ...
```

Converting the first data packet to text and trying to decode it using Base64, gives us an error due to the presence of colons(`:`) in the string, which is illegal for a base64 encoded string. This points us towards a single letter that is held between two colons in the unhexlified string. 
```
                                                                                  -----vvv-----
4yCK6F0xEs3vk0SRYA3t0sTQKJaFtqBl3P3ItFdufJtnKOIgHxYBWIQGJddGO28GKBtYowMnt2i5952qnKVYptX:n:wsIdZVn5F2UedZAqwjSwiJDGFhamjMDMWk5tzOCafGy2sSeVGdgy1uqtlHMQRL4lRAygqkao9qIY5LrQ5bHcxqD7zW9J15oAoO9amLnTtnm0ltQ5TJZ6bg7T4Vt940
```

```python
    flag = {}
    with open("ipv6.txt", 'r') as F:
        for l in F.readlines():
            f,d = l.strip().split('\t')
            b = binascii.unhexlify(d).split(b':')
            f = int(f[2:],16)
            flag[f] = b[1].decode()        
            print(f"{f:3d} {b[1].decode()}")

    print(''.join([flag[x] for x in sorted(flag.keys())]))

    # DANTE{l4b3l5_c4n_m34n_m4ny_7h1ngs}
```

#### Almost Perfect Remote Signing
` I c4n't re?d you Are_you a beacon fAom 1200 0r smthing?`

We are given a WAV file. Loading the file into Audacity and examing both the waveform and spectrogram does not reveal any information, except that the sound starts and ends abruptly, which seems to indicate some kind of a digital data encoding.

Searching for the abbreviation of the challenge title, APRS, leads us to this [page on SignalsWiki](https://www.sigidwiki.com/wiki/Automatic_Packet_Reporting_System_(APRS)). Automatic Packet Reporting System is a packet system for real time data communications. Used by hams for location reporting, weather stations etc. APRS is transported over the AX.25 protocol using 1200 bit/s Bell 202 AFSK on frequencies located within the 2 meter amateur band. 

Further research, led me to a tool called [DireWolf](https://github.com/wb2osz/direwolf) on GitHub, which has a set of utilities to deal with AX.25.  I used a tool in the toolkit called `atest` to extract data from the wave file, which looks like this: 
```
    DECODED[1] 0:02.175 N0CALL audio level = 63(33/33)     
    [0] N0CALL>APN001:!4346.02N\01115.45EgHello flag! Pkt 0002/1080
    ------
    U frame UI: p/f=0, No layer 3 protocol implemented., length = 61
    dest    APN001  0 c/r=1 res=3 last=0
    source  N0CALL  0 c/r=1 res=3 last=1
    000:  82 a0 9c 60 60 62 e0 9c 60 86 82 98 98 e1 03 f0  ...``b..`.......
    010:  21 34 33 34 36 2e 30 32 4e 5c 30 31 31 31 35 2e  !4346.02N\01115.
    020:  34 35 45 67 48 65 6c 6c 6f 20 66 6c 61 67 21 20  45EgHello flag! 
    030:  50 6b 74 20 30 30 30 32 2f 31 30 38 30           Pkt 0002/1080
```
As depicted, there are 1080 packets of data - each containing a GPS coordinate, an icon `g` and the label `Hello flag!`. Given that the label and the icon are repeated for each packet, I extracted the GPS coordinates and imported it into GPSVisualizer. With moderate tweaking, and changing the plot type from tracks to waypoints, we get to read the flag. There are some displacements, but it was close enough to give us the flag : `DANTE{FLAG_REPORTING_SYSTEM}`

![](2023-06-04-00-11-52.png)

#### Imago Qualitatis
`A wondrous electromagnetic wave was captured by a metal-stick-handed devil. "But.. What? No, not this way. Maybe, if I turn around like this... Aha!"`

Use `gqrx` to load the given raw file. The file contains the raw IQ signals and processing the data using default settings shows the Dante logo image interspersed with the characters of the flag. Capturing the displayed characters gives the flag: `DANTE{n3w_w4v35_0ld_5ch00l} ` 

![](2023-06-04-00-19-11.png)

#### Hanging Nose
`Divine Comedy-themed Christmas tree baubles: that's the future of the ornaments business, I'm telling you!`

We are given an STL file of a christmas tree ornament. Examining the inside of the object reveals the flag.

![](dante_ornament.png)

#### DIY Enc
`I met a strange soul who claimed to have invented a more robust version of AES and dared me to break it. Could you help me?`


#### PiedPic
`Dante took many pictures of his journey to the afterlife. They contain many revelations. I'll give you one of these pictures if you'll give me one of yours!`

### After the CTF
#### Adventurer's Knapsack
`For every good trip in the afterworld you need a good knapsack!`


### Resources
* http://www.aprs.org/iss-aprs/issicons.html
* http://www.aprs.org/doc/APRS101.PDF
* https://inst.eecs.berkeley.edu/~ee123/sp15/lab/lab6/Lab6_Part_B-APRS.html
* https://github.com/BlackVS/Awesome-CTS
* https://crypto.stackexchange.com/questions/50068/how-to-attack-merkle-hellman-cryptosystem-if-the-first-element-in-the-superincre
* http://www.cs.sjsu.edu/faculty/stamp/papers/topics/topic16/Knapsack.pdf


### List
|Category|Challenge|Description
|----|----|----
|Crypto|Adventurer's Knapsack|Merkle-Hellman Knapsack cryptography
|Crypto|DIY enc|
|Crypto|PiedPic|Image cryptography
|Crypto|Small Inscription|
|Forensics|Almost Perfect Remote Signing|APRS signals in wav
|Forensics|Dirty Checkerboard|
|Forensics|Do You Know GIF?|
|Forensics|Imago Qualitatis|text/image in Raw IQ data
|Forensics|Routes Mark The Spot|PCAP with ipv6 traffic
|Forensics|Who Can Haz Flag|
|Misc|Demonic Navigation Skills|DNS
|Misc|Flag Fabber|
|Misc|Gloomy Wood|
|Misc|Hanging Nose|
|Misc|HellJail|
|Misc|StrangeBytes|
|Misc|Survey|
|Pwn|Dante's Notebook|
|Pwn|Infernal Break|
|Pwn|Sentence To Hell|
|Pwn|Soulcode|
|Reverse|Rusty Safe|
|Web|CryptoMarket|
|Web|Dante Barber Shop|
|Web|Dumb Admin|
|Web|FlagShop|
|Web|SecureHashedDb|
|Web|Unknown Site 1|
|Web|Unknown Site 2|