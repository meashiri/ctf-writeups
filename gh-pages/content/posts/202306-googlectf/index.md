---
title: "Google CTF"
date: 2023-06-23T22:15:00-04:00
categories: [ctf, writeup]
tags: [lcg, lua, hookup, jxl, ]
cover:
    image: googlectf_banner.png
---

This was a very tough, high quality CTF challenge by Google. Due to some unforeseen circumstances, I had very little time to play in the CTF, and whatever challenges I was able to solve, my team mates had gotten there ahead of me. I am capturing some of the learnings from this CTF for future reference. 
<!--more-->


#### ZERMATT (Rev)

`Roblox made lua packing popular, since we'd like to keep hanging out with the cool kids, he's our take on it.`

We are given an obfuscated Lua program. Running the program prompts us for input. Given an arbitrary input, it prints "LOSE" and exits.

```
 _____             _     ___ _____ ____ 
|   __|___ ___ ___| |___|   |_   _|  __|
|  |  | . | . | . | | -_| -<  | | |  __|
|_____|___|___|_  |_|___|___| |_| |_|   
              |___|       ZerMatt - misc 
> abcd
LOSE
```

I learnt that everything in Lua can be assigned to variables, values, functions, imports etc. While we can spend a lot of time debugging or trying to unobfuscate the code, there was a great suggestion by an user on discord to use `debug.hook` on function `string.char`. This is the function that is used to obtain the character from its ascii value in decimal. 

We can use a simple function to accumulate all the characters that were converted from their numeric values in a string and print it in each iteration. The following code would be added to `zermatt.lua` file.

```lua
        local chars = '';
        function hookfunction(event)
            if debug.getinfo(2, 'f').func == string.char then
            chars = chars .. string.char(select(2, debug.getlocal(2, 1)));
            print(chars);
            end
        end

        debug.sethook(hookfunction, 'c') -- hook a function for all function calls ['c']
```

The program then runs normally and waits for input. Upon supplying an arbitrary input, it assembles the correct flag for comparison and ends with an error message. However, with the hook, the flag is printed to stdout.

```
Jstringcharbytesubbit32bitbxortableconcatinsertiowrite _____             _     ___ _____ ____ 
|   __|___ ___ ___| |___|   |_   _|  __|
|  |  | . | . | . | | -_| -<  | | |  __|
|_____|___|___|_  |_|___|___| |_| |_|   
              |___|       ZerMatt - misc 
@~Eۧsread1/7#49,!>,/"/".;/"/؜CJprintq&T)vF%0vBr__index__newindex> CTF{At_least_it_was_not_a_bytecode_base_sandbox_escape}LOSE
LOSE
```

`flag: CTF{At_least_it_was_not_a_bytecode_base_sandbox_escape}`

#### PAPAPAPA
`Is this image really just white?`


```
0000009e: ffc0          // SOF0 segement
000000a0: 0011          // length of segment depends on the number of components
000000a2: 08            // bits per pixel
000000a3: 0200          // image height
000000a5: 0200          // image width  --> change to 0210 = 528
000000a7: 03            // number of components (should be 1 or 3)
000000a8: 013100        // 0x01=Y component, 0x22=sampling factor, quantization table number
000000ab: 023101        // 0x02=Cb component, ...
000000ae: 033101        // 0x03=Cr component, ...
```






* https://github.com/google/google-ctf/tree/master/2023
* https://github.com/abhishekg999/GoogleCTF-2023
* https://security.stackexchange.com/questions/4268/cracking-a-linear-congruential-generator
* https://ctftime.org/writeup/23246
* https://tailcall.net/posts/cracking-rngs-lcgs/
* https://github.com/Liorst4/uxn-disassembler
* http://dougkerr.net/Pumpkin/articles/Subsampling.pdf


