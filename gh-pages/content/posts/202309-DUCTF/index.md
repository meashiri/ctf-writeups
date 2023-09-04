---
title: "202309 DUCTF"
date: 2023-09-02T14:52:12-04:00
categories: [ctf, writeup]
tags: [punycode,]
math: true
cover:
    image: ductf-cover.png
---
This was a very high quality CTF with over sixty (!!) challenges.  This CTF had everything we need in a CTF - plenty of unique challenges, wide variety, beginner to advanced level of difficulty and immediate release of official writeups. Capturing a mix of both my solutions and official solutions for future reference. 
<!--more-->

### Beginner Challenges
#### Pynycode
`I've never seen a Python program like this before. [Author: hashkitten]`

We are given a python source file that is coded in `punycode`. Researching on punycode, gives us the following definition from Wikipedia.

`Punycode is a representation of Unicode with the limited ASCII character subset used for Internet hostnames. Using Punycode, host names containing Unicode characters are transcoded to a subset of ASCII consisting of letters, digits, and hyphens, which is called the letter–digit–hyphen (LDH) subset. For example, München (German name for Munich) is encoded as Mnchen-3ya.`

```python
#coding: punycode
def _(): pass
('Correct!' if ('Enter the flag: ') == 'DUCTF{%s}' % _.____ else 'Wrong!')-gdd7dd23l3by980a4baunja1d4ukc3a3e39172b4sagce87ciajq2bi5atq4b9b3a3cy0gqa9019gtar0ck
```

So, in essence, it is a self-modifiable codec scheme and Python has built-in support for it. All the ASCII characters are extracted from the string, and the non-ascii (unicode) characters are encoded at the end to be inserted into the appropriate positions in the string after decoding. I tried to use python's built in `decode()` function to decode the source or even the specific string that appears after `Wrong!')`. They did not yield any comprehensible solution. So, I brute forced the subset of the bytestream that would provide me a comprehensible solution. I did not pay close attention to the output and missed the fact that at offset=17bytes, the sourcefile decodes to readable python code, albeit with unicode characters.

```python
s = open("pyny.py", "rb").read()

for i in range(len(s)):
    print(f"Offset: {i} : {s[i:].decode('punycode')}")
    input()
# shows that at offset 17, we get a proper python code with unicode text
'''
Offset: 17 : 
def ᵖʸᵗʰºⁿ_ʷªʳᵐᵘᵖ(): pass
ᵖʳᵢⁿᵗ('Correct!' if ᵢⁿᵖᵘᵗ('Enter the flag: ') == 'DUCTF{%s}' % ᵖʸᵗʰºⁿ_ʷªʳᵐᵘᵖ.__ⁿªᵐᵉ__ else 'Wrong!')
'''
```

So, if I had paid close attention, the final solution would have been: 
```python
In [1]: open('pyny.py', 'rb').read()[17:].decode('punycode')    # the first 17 bytes are the 'coding' declaration, that should be removed. 
Out[1]: "\ndef ᵖʸᵗʰºⁿ_ʷªʳᵐᵘᵖ(): pass\nᵖʳᵢⁿᵗ('Correct!' if ᵢⁿᵖᵘᵗ('Enter the flag: ') == 'DUCTF{%s}' % ᵖʸᵗʰºⁿ_ʷªʳᵐᵘᵖ.__ⁿªᵐᵉ__ else 'Wrong!')"

In [2]: exec(open('pyny.py', 'rb').read()[17:].decode('punycode'))
Enter the flag: DUCTF{python_warmup}
Correct!
```

#### Needle in IAM
`I've been told the flag I need is in description of this role, but I keep getting an error with the following command. Surely there's another way? Author:[BootlegSorcery@]`

**`gcloud iam roles describe ComputeOperator --project=<PROJECT>`**

We are given credentials to a Google cloud account as `credentials.json`. From that JSON file, we get the project-id as `needle-in-iam`.
```json
{
  "type": "service_account",
  "project_id": "needle-in-iam",  <<--- project-id
  ...
  ...
  "universe_domain": "googleapis.com"
}
```
Using that project id, we can list the IAM roles defined. In this list, we get the flag in the description of the `ComputeOperator` role. 

```bash
% gcloud iam roles list --project 'needle-in-iam' | grep -B3 "ComputeOperator"
---
description: DUCTF{D3scr1be_L1ST_Wh4ts_th3_d1fference_FDyIMbnDmX}
etag: BwYDv1xX9Y4=
name: projects/needle-in-iam/roles/ComputeOperator
```
#### helpless
`I accidentally set my system shell to the Python help() function! Help!!`
`The flag is at /home/ductf/flag.txt. Author: [hashkitten]`

We are given a SSH credentials and a challenge server. 

```
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sun Sep  3 18:12:09 2023 from 10.152.0.21

Welcome to Python 3.10's help utility!

If this is your first time using Python, you should definitely check out
the tutorial on the internet at https://docs.python.org/3.10/tutorial/.

Enter the name of any module, keyword, or topic to get help on writing
Python programs and using Python modules.  To quit this help utility and
return to the interpreter, just type "quit".

To get a list of available modules, keywords, symbols, or topics, type
"modules", "keywords", "symbols", or "topics".  Each module also comes
with a one-line summary of what it does; to list the modules whose name
or summary contain a given string such as "spam", type "modules spam".

help> 
```
To get the flag, 
1. Enter a legitimate python help topic that is over one page long, so that a paginator is invoked. I used `os`.
1. The help for module `os` is displayed and paused after the first page
1. The paginator has a colon `:` prompt
1. At the prompt, enter another colon and `e`, i.e `:e`
1. The prompt changes to `Examine:`. Enter `flag.txt`
1. The file `flag.txt` is loaded into the current buffer and displays the flag `DUCTF{sometimes_less_is_more}`

####

### Crypto
#### apbq rsa i
`Just a simple RSA problem with some extra equations.`
We are given this challenge source

```python
p = getPrime(1024)     # strong prime
q = getPrime(1024)     # strong prime
n = p * q
e = 0x10001

hints = []
for _ in range(2):
    a, b = randint(0, 2**12), randint(0, 2**312)
    hints.append(a * p + b * q)

FLAG = open('flag.txt', 'rb').read().strip()
c = pow(bytes_to_long(FLAG), e, n)
print(f'{n = }')
print(f'{c = }')
print(f'{hints = }')
```
This is textbook RSA with no structural issues. To solve it, we are given two leaks about \\(p\\) and \\(q\\) as hints.
The hints 

$$
    h_1 = a_1 * p + b_1 * q  \\\
    h_2 = a_2 * p + b_2 * q  \\\
    \text{ where }0 \le a_n \le 2^{12} \text{   and   } 0 \le b_n \le 2^{312} \\\
    \text{ Thus, } a_n \ll b_n \text{ and can be bruteforced}
$$

Continuing, 

$$
    h_1 * a_2 = a_1 * a_2 * p + b_1 * a_2 * q \\\
    h_2 * a_1 = a_1 * a_2 * p + b_2 * a_1 * q \\\
    \therefore h_2 * a_1 - h_1 * a_2 = (b_2 * a_1 - b_1 * a_2) *q \\\
$$

The factor \\((b_2 * a_1 - b_1 * a_2)\\) should be small, as \\(b_1 \approx b_2 \text{  and   } a_1 \approx a_2\\). Thus, \\(GCD(h_2 * a_1 - h_1 * a_2, n) \overset{!}{=} \text{q      } \\)

So, we will determine `q` by bruteforcing \\((a_1, a_2)\text{  in [0 .. }2^{12}]\\) 

```python
# We are given n, e, c, hints=[h1, h2]
    found = False
    for a1 in range(1, 2**12):
        for a2 in range(1, 2**12):
            hint = h2 * a1 - h1 * a2 
            q = math.gcd(hint, n)
            if (q > 1): 
                # apply textbook RSA
                p = n // q
                phi = (p-1)*(q-1)
                d = inverse(e, phi)
                m = long_to_bytes(pow(c, d, n))
                if (b'DUCTF' in m):
                    print(f"{a1} {a2} | {m}")
                    found = True
                    break
        if (found): 
            break
# 410 761 | b'DUCTF{gcd_1s_a_g00d_alg0r1thm_f0r_th3_t00lbox}'
```

### Misc 
#### Mini DNS Server


* https://cabulous.medium.com/dns-message-how-to-read-query-and-response-message-cfebcb4fe817


#### Simple FTP Server

```bash
% nc 2023.ductf.dev 30029
220 vsFTPd (v2.3.4) ready...
LIST
150 Here comes the directory listing.
drwxr-xr-x 1 user group 4096 Aug 04 02:02 usr
drwxr-xr-x 1 user group 4096 Aug 04 02:06 lib64
drwxr-xr-x 1 user group 4096 Aug 21 01:13 lib
drwxr-xr-x 1 user group 4096 Aug 21 01:14 bin
drwxr-xr-x 1 user group 4096 Aug 21 01:12 kctf
drwxr-xr-x 1 user group 4096 Aug 30 04:23 chal
226 Directory send OK.
CWD chal
250 OK.
LIST
150 Here comes the directory listing.
-rwxr-xr-x 1 user group 7151 Aug 30 04:23 pwn
-rw-r--r-- 1 user group 27 Aug 31 02:14 flag.txt
226 Directory send OK.
RETR flag.txt
150 Opening data connection.
226 Transfer complete.
DUCTF{- Actually no, I don't feel like giving that up yet. ;)
RETR pwn
<prints source file>
...
```
Retrieving the `pwn` file gives the source code of the FTP server. It is a light-weight FTP server that is written in Python, which uses python's reflection features to map commands to methods. The reflection is done by the line: `func=operator.attrgetter(cmd)(self)`

```python
    def run(self):
        sys.stdout.buffer.write('220 vsFTPd (v2.3.4) ready...\r\n'.encode(ENCODING)) # Red Herring

        while True:
            sys.stdout.flush()
            recv=sys.stdin.buffer.readline()
            if not recv: break
            else:
                lst = recv.decode(ENCODING).strip().split(" ", 1)
                if len(lst) < 2:
                    cmd, args = lst[0], ""
                else:
                    cmd, args = lst      
                try:
                    func=operator.attrgetter(cmd)(self)
                    msg = func(args)
                    sys.stdout.buffer.write(f'{msg}'.encode(ENCODING))
                except Exception as e:
                    sys.stdout.buffer.write(f'500 Sorry. {e}\r\n'.encode(ENCODING))

```

```bash
% nc 2023.ductf.dev 30029
__class__.__init__.__globals__.__getitem__ FLAG
DUCTF{15_this_4_j41lbr34k?}

# official solution
__init__.__globals__.get FLAG
```

#### 
### Resources and writeups
* Official writeups: https://github.com/DownUnderCTF/Challenges_2023_Public


### Challenges
{{< collapse "Expand to see the list of challenges" >}}
|Category|Challenge|Description
|----|----|----
beginner |All Father's Wisdom|
beginner |Needle In IAM|
beginner |Survey|
beginner |Welcome to DUCTF!|
beginner |blinkybill|
beginner |complementary|
beginner |confusing|
beginner |discord|
beginner |downunderflow|
beginner |flag art|
beginner |helpless|
beginner |one byte|
beginner |proxed|
beginner |pyny|
beginner |randomly chosen|
beginner |static file server|
beginner |the bridgekeepers 3rd question|
beginner |xxd-server|
beginner |𝕏|
blockchain |Another Please|
blockchain |Eight Five Four Five|
blockchain |Immutable|
blockchain |Monkeing Around|
crypto |apbq rsa ii|
crypto |apbq rsa i|
crypto |dilithium±|
crypto |encrypted mail|
crypto |fnv|
crypto |handshake|
crypto |hhhhh|
crypto |lcg card gimmicks|
misc |My First C Program!|
misc |Rogueful Helper|
misc |SimpleFTPServer|
misc |Smart Calculator|
misc |baby ruby|
misc |daas|
misc |impossible|
misc |mini dns server|
misc |real baby ruby|
osint |Bridget's Back!|
osint |Comeacroppa|
osint |Excellent Vista!|
osint |Shipwrecked|
osint |faraday|
osint |monke bars|
pwn |baby crm|
pwn |binary mail|
pwn |return to monke|
pwn |roppenheimer|
pwn |safe calculator|
pwn |shifty mem|
pwn |the great escape|
pwn |vroom vroom|
rev |SPACEGAME|
rev |advanced vector expositions|
rev |masked squares flag checker|
rev |number theoretic flag checker|
rev |sideways|
rev |wrong signal|
web |0day blog|
web |actually-proxed|
web |cgi fridays|
web |crossed monkes|
web |grades_grades_grades|
web |secure blog|
web |smooth jazz|
web |strapi in|
{{< /collapse >}}