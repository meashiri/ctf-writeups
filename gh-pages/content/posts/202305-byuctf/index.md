---
title: "BYU CTF"
date: 2023-05-19T23:01:20-04:00
categories: [ctf, writeup]
tags:
cover:
    image: "byuctf_logo.jpg"
---

Solved a few challenges in the BYU CTF organized by the Brigham Young University Cyberia academic team. 

<!--more-->

### 𐐗𐐡𐐆𐐑𐐓𐐄?

We are given a PNG file with some uncommon runes/symbols.  I checked the symbol cipher page at dcode.fr and could not spot the scheme used. 

![](chall_deseret.png)

Then I noticed that the title of the puzzle is in unicode characters. So, I searched for the first character in the challenge title and it led me to this site: https://graphemica.com/%F0%90%90%97  This page indicates that this is an character from the Deseret alphabet. So searching some more led me to this page, https://www.2deseret.com/ which offers a converter from English alphabet to Deseret and vice versa.

Entering the characters from the challenge title translates to the phonetic equivalent of CRYPTO `/K/R/IH/P/T/OH/`

The challenge text seems to translate to `BE WHY YOU SEE TEA F DESERET MEANS /H/U/N/IH /b/`

![](2023-05-20-16-11-33.png)

Phonetically, it seems to be saying `byuctf deseret means honey`. Inserting the braces, gives us the flag.

Flag: `byuctf{deseret_means_honey}`

### Poem

We are given the following text in the challenge description. 

`epcndkohlxfgvenkzcllkoclivdckskvpkddcyoceipkvrcslkdhycbcscwcsc`

Dcode cipher identifier suggested the Keyboard Change Cipher as the top choice. Exploring it further, the combination of Alphabetical -> QWERTY seems to give a sensible sentence.

`thefragisbyuctfamessagesocrealacharrengetohackelsarinewelevele`

But, not exactly.  It seems that `r` and `l` have been switched. So, switching all `l` and `r` gives us the following sentence.

`theflagisbyuctfamessagesoclearachallengetohackersalinewerevere`

Adding a space after each word, gives us a proper sentence. 

`the flag is byuctf a message so clear a challenge to hackers a line we revere`

Flag: `byuctf{a message so clear a challenge to hackers a line we revere}`

### Compact

![](chall_latin.png)

Using the symbol cipher list on dcode.fr, we are able to determine that this cipher is Dotsies Font.

![](2023-05-21-01-27-41.png)

A simple matter of transcribing the symbols, yeilds the flag.

Flag: `byuctf{well its definitely more compact}`

### XKCD 2637

The challenge title refers to this edition of the XKCD comics.

![](roman_numerals_2x.png)

The notion is to represent a number in romal numerals, but replace the roman letters with the decimal equivalent. So, 123 represented in roman is CXXIII, and will be written as 1001010111  `aka 100-10-10-1-1-1` in XKCD terms.

We are given a challenge server, that would serve 500 of these problems and if we answer them all correctly, we would get the flag.  

First, we formulate our approach:
1. We will be given a math statement in xkcd form (eg. `501010 + 101010`)
1. Turn this into a proper roman numeral representation ( `LXX + XXXV`)
1. Turn each roman numeral to decimal (`70 + 35`)
1. Evaluate this statement to get the answer (`105`)
1. Turn this answer in decimal to roman representation (`CV`)
1. Turn the roman representation to XKCD representation (`1005`)
1. Send this as the answer to the server. 

```
    501010 + 1010105 ==> LXX + XXXV ==>  70 + 35  ==> eval() ==> 105 ==> CV ==> 1005 (answer to be sent)

```

The solution for doing the calculation and sending the results to the challenge server is given below. 

```python
    '''
        # included some helper routines to do roman to decimal and decimal to roman conversions
        def roman_to_int(stringvalue)
        def int_to_roman(intvalue)
    '''
    def xkcd_to_roman(input):
        input = input.replace('1000', 'M')
        input = input.replace('500', 'D')
        input = input.replace('100', 'C')
        input = input.replace('50', 'L')
        input = input.replace('10', 'X')
        input = input.replace('5', 'V')
        input = input.replace('1', 'I')
        return input

    def roman_to_xkcd(input):
        input = input.replace('M', '1000')
        input = input.replace('D', '500')
        input = input.replace('C', '100')
        input = input.replace('L', '50')
        input = input.replace('X', '10')
        input = input.replace('V', '5')
        input = input.replace('I', '1')
        return input

    tries = 0
    while(tries<500):
        line = r.recvuntil(b'=')
        tries += 1
        #print(line)

        l = line.strip().split()
        S = ""
        S+= str(roman_to_int(xkcd_to_roman(l[0].decode())))
        S+= l[1].decode()
        S+= str(roman_to_int(xkcd_to_roman(l[2].decode())))
        
        A = roman_to_xkcd(int_to_roman(eval(S)))
        print(f"{tries}: {line} | {S} | {A}")
        r.sendline(A)

    r.interactive()
```
Flag: `byuctf{just_over_here_testing_your_programming_skills_:)}`

### Scooter Web
1. Get EXIF comments from 8 images. We get eight 196 character hex strings 
1. Take every combination of 7 hex strings and XOR them. 
1. One of the combinations will yield the flag.

```python
from Crypto.Util.strxor import strxor
from binascii import unhexlify

hex_strings = [
"0b6230db558118b1fe...f4255bb3a3307937c7707",
"8fd2604fe1f8fedda3...e0176a225c42693872736",
"a2dc9c847c41d04cef...c57510caa135f06130c43",
"d5b6b130f04a14ffab...3e637335e5ab3d88f0cc0",
"75bdfbbe1c2e465af4...43823dc35cf34ea437b4e",
"7dd7816c3b2a2d36ba...f6a4ce1738232fb31f6a1",
"b8dc32c994e2393ad3...04a61e486cd2520e1c6b0",
"54a8bbe6e3dc4d8718...1d268231ef1da05b760a3",
]

for i in range(8):
    result = b'\x00'* 96
    for j in range(8):
        if (i != j):
            hex_j = unhexlify(hex_strings[j])
            result = strxor(result, hex_j)
    print(f"{i} --> {result}")                  
```

### Ducky 1

```
DuckToolkit-master % python3 ducktools.py -l us -d ../ducky1_inject.bin /dev/stdout
[+] Reading Duck Bin file
  [-] Decoding file
  [-] Writing ducky text to /dev/stdout
DELAY
byuctf{this_was_just_an_intro_alright??}
[+] Process Complete
```
### Ducky 2

```
    for i in `cat langs.txt` 
    for> do
    for> echo LANG=$i     
    for> python3 ducktools.py -l $i -d ../ducky1_inject.bin /dev/stdout | grep "byuctf{"
    for> done
    LANG=ch
    LANG=de
    LANG=fi
    LANG=mx
    LANG=sk
            byuctf{makesureyourkeyboardissetupright)@&%(#@)!(#*$)}
    LANG=us
    LANG=gb
    LANG=pt
    LANG=be
    LANG=it
    LANG=cz
            byuctf{makesureyourkeyboardissetupright'@&%(#@'!(#*$'}
    LANG=hr
    LANG=dk
    LANG=fr
    LANG=br
    LANG=ca
    LANG=si
    LANG=se
    LANG=es-la
    LANG=ca-fr
    LANG=no
    LANG=es
```
### Ducky 3

```python
chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_"

with open('ducky3_inject.bin', 'rb') as F:
    duckbin = F.read()
    ducks = hexlify(duckbin)
    lookup = {}
    i = 0
    for c in chars:
        lookup[ducks[i:i+4]]=c
        i+=4

    s = ""
    while(i<len(ducks)):
        try:
            print(f"{ducks[i:i+4]} --> {lookup[ducks[i:i+4]]}")
            s += lookup[ducks[i:i+4]]
        except Exception as e:
            print (e)
            #continue
        i+=4    
    print(s)

    # byuctf{1_h0p3_y0u_enj0yed-thi5_very_muCH}
```

## Writeups
* Official writeups/challenges : https://github.com/BYU-CSA/BYUCTF-2023/


## Challenges

|Category|Challenge|Description
|----|----|----
|Crypto|Compact| *
|Crypto|Poem| *
|Crypto|RSA1|
|Crypto|RSA2|
|Crypto|RSA3|
|Crypto|RSA4|
|Crypto|RSA5|
|Crypto|𐐗𐐡𐐆𐐑𐐓𐐄?| *
|Forensics|Bing Chilling|
|Forensics|CRConfusion|
|Forensics|Paleontology|
|Forensics|Q10|
|Forensics|ScooterWeb|*
|Forensics|What does the cougar say?|
|Forensics|kcpassword|
|Jail|Builtins 1|
|Jail|Builtins 2|
|Jail|Leet 1|
|Jail|Leet 2|
|Jail|a-z0-9|
|Jail|abcdefghijklm|
|Jail|nopqrstuvwxyz|
|Misc|006 I|
|Misc|006 II|
|Misc|006 III|
|Misc|Collision|
|Misc|Hexadecalingo|
|Misc|Lost|
|Misc|National Park|
|Misc|PBKDF2|
|Misc|Sanity Check|
|Misc|Sluethr|
|Misc|Survey|
|Misc|xkcd 2637|*
|OSINT|Criterion|
|OSINT|It All Ads Up|
|OSINT|It All Ads Up 2|
|OSINT|Legoclones 1|
|OSINT|Legoclones 2|
|OSINT|Legoclones 3|
|OSINT|Legoclones 4|
|OSINT|Legoclones 5|
|Pentesting|MI6configuration 1|
|Pentesting|MI6configuration 3|
|Pentesting|MI6configuration 4|
|Pentesting|VMception|
|Pwn|2038|
|Pwn|ScooterAdmin1|
|Pwn|ScooterAdmin2|
|Pwn|ScooterAdmin3|
|Pwn|Shellcode|
|Pwn|VFS 1|
|Pwn|frorg|
|Rev|Chain|
|Rev|Chicken Again|
|Rev|Ducky1|*
|Rev|Ducky2|*
|Rev|Ducky3|*
|Rev|Go|
|Rev|RevEng|
|Rev|Sassie|
|Rev|bad2|
|Rev|obfuscJStor|
|Web|HUUP|
|Web|Notes|
|Web|urmombotnetdotnet.com 1|
|Web|urmombotnetdotnet.com 2|
|Web|urmombotnetdotnet.com 3|
|Web|urmombotnetdotnet.com 4|
|Web|urmombotnetdotnet.com 5|