---
title: "202304 JerseyCTF"
date: 2023-04-15T13:44:00-04:00
categories: [ctf, writeup]
tags:
cover:
  image: "jerseyctfIII.png"
---

Checked out some challenges in JerseyCTF
<!--more-->

#### Quick Hits
##### crypto/missing employee-1 

    simple Base64 decode

##### crypto/Jack-and-Jill 

    The name suggests Hill cipher and so it is. 
    https://www.dcode.fr/hill-cipher -> `jctf{hiTHEREwelcomeTOlinearALGEBRAZ}`

##### crypto/space-dust
    file: message_from_tom.zip -> message_from_tom.txt -> base64 -d -> PNG 


##### crypto/roko-cipher-in-the-console <cite>[^1]</cite>
    hint: key = ROKO
    000000000000000111111111
    123456789abcdef012345678
    f1stg}th10_ej{s__act_nam
    4..3........15....2.....

##### crypto/birthdays

`jctf{Greetings_from_the_real_universe}`


#### crypto/here-we-go-again
    file: ughNotAgain.wav

    Spectogram view
    NB2HI4DTHIXS64DBON2GKYTJNVXGG33NF5TWE4DJGQ2GMMA===  
    .- ----. ... ---.. .-. -- .-. -.. -..- -.

https://pastebin.com/gbpi44f0

#### crypto/holy-hECCk

    `
        HOLY ELLIPTIC CURVE, BATMAN! RB has trapped the dynamic duo of Anna and Simon in one of his cruel cryptographic contraptions. Each member has been locked in a sound-proof box with only a small interface in front of them to send information to one another. Displayed on the interfaces are an elliptic curve equation, a private key, and an input box to send information to their partner.
        Anna's private key is 167. Simon's private key is 152. The pictured elliptic curve is y^2 = x^3 + 18x + 9 (mod 8011).
        Before heading off to perform his heist, RB cackled and told Dr. Tom that the prisons would not open until they both input the shared secret key they can generate from the Elliptic Curve algorithm using the perfect generator point on the curve with the greatest x-coordinate. Out of the two y-coordinates on the generator point's x-coordinate, the lower y-coordinate will be used.
        Will Anna and Simon escape to stop the vile villainy of the RB?
        Flag Format: jctf{(0,0)}
    `


#### crypto/distress-signal

    `
        ACM member Hal wasn't paying attention and walked under the clocktower. Something happened and they were sent incredibly far away! We guess that the rogue AI turned the clocktower into a transportation device. The location of his perilous plight is Space Sector 19 near the moon Vergo 87.
        In order to contact other members of ACM and Aero to get rescued, he must use their secure means of communication using Menezes Vanstone Elliptic Curve Cryptography. The agreed upon elliptic curve that they use for emergencies of this kind is the following: y^2 = x^3-43x+166(mod 8011).
        However, Hal is not the brightest lantern of the bunch and can't recall which of three points he should use as the scheme's generator, only that he should use the point with the highest order. The three points that Hal can remember are: (59,1175), (752,4670), and (318,4906). SIGmaster Kilowog is who Hal will be trying to contact, and Kilowog has a public key of (273, 517).
        Hal's plaintext message of his sector and planet location is m = {19,87}. Hal has chosen his secret key k = 3. What is the encrypted SOS message that Hal sends to Kilowog in this Menezes Vanstore Elliptic Curve scheme?
        Flag Format: jctf{(0,0),0,0}
    `

#### crypto/opening-act

    `
        Somehow WJTB got Taylor Swift to perform at NJIT and we've got to maintain her setlists for the ongoing Eras Tour during PizzaPalooza next week.
        Taylor has just sent you a message that contains the name of the song that the singer/songwriter wants to use as the opening act to her next performace. However, to avoid any information about the upcoming show from leaking to the press, the message has been encrypted via RSA. The message also includes Taylor's digital signature to verify its legitimacy. The received message is: "14909242".
        Taylor's public key information is the following: (m = 62473207, e = 571). Unfortunately, in the hustle and bustle of managing the start of the tour, you have misplaced some of your public and private key information. You know that part of your public key is: (g = 877) and part of your private key is: (p = 5689, q = 5693).
        Determine the remaining values of your private and public key and decrypt Taylor's memo in a way that ensures confidentiality and integrity.
        Flag Format: jctf{0}
    `
[^1]: Solved after the CTF was complete. Captured here for educational purposes. 