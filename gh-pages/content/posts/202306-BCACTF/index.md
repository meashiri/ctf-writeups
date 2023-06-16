---
title: "BCA CTF"
date: 2023-06-11T10:49:45-04:00
categories: [ctf, writeup]
tags:
cover:
    image: bcactf_banner.png
---

I was severely constrained for time this weekend and was not able to participate in the CTF. However the challenges looked very interesting and I solved a few of them after the CTF. I also scoured through some writeups to capture learning for future use. 
<!--more-->
### Crypto
#### Dots and Dashes
`My friend sent me a message by flashing his flashlight, and I recorded it using .'s and -'s. Can you help me decode it?`

code.txt: `-..---.--..---..-..----.-..---..-...-.---..--..--....-..-..-...---..-----.-.-.---.-.....-.-.---.-.-.-.-.--.----.-...-.----..--..-.-.....-.--..-.--..-----...--.---..-.-.-.---.-.-.-.....--...--.--...-----..---.--..-.----..-.-.--..-.---.....-.`

Not morse code, as there are no separators. Assume to be binary. Translate `-.` to `01` and decode.

```bash
    % cat dotdash_code.txt | tr '\-.' '01' | perl -lpe '$_=pack"B*",$_'
    bcactf{n0T_QU!t3_M0r5E_981454}
```
#### Many time pad
`I heard that one-time pads are unbreakable! I'm going to use it for everything!!`


#### Here's my Hamsta
```
    Hi there. This is my my hamster. He LOVES to run.
    The further he runs, the more of the flag you get
    How many miles do you want him to run? 11
    Awesome, (11 <= 11) is true, so my hamster's ready to run!
    Flag is: bcactf{w3lc
    . . .
    Welp! That was 11 miles, time to stop
    But let's do it again!
    How many miles do you want him to run? -47
    Awesome, (-47 <= 11) is true, so my hamster's ready to run!
    Flag is: bcactf{w3lcom3_TT0_PWN;__h4mster_8e9d89a}
```
