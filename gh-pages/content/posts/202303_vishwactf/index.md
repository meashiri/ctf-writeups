---
title: "Vishwactf "
date: 2023-03-31T02:56:46-04:00
tags: [usbcap, steg, wav, shamir-sharing]
categories: [ctf, writeup]
cover:
    image: "vishwactf-logo.png"
---

#### 1nj3ct0r

Standard USB HID capture in the pcapng. Look for `usbcap.data` where `usb_datalen==2` and translate.

#### Quick Heal 

Pieces of QRcode all over the video. Step through with VLC and capture the frames. Resize and assemble with Gimp. Gives half a flag. `ffmpeg` to extract audio. Open in audacity and view spectrogram. Gives morse code that will give second half of the flag. 

#### Mystery of Oakville Town

Steghide on the photo -> gives license plate of escape vehicle. Search sqlite3 db for the escape_vehicle on Mar 27 and 28. Find all connected towns for each traffic cam by select distinct. Finally cancel out the back-and-forth movement of the car to find the final direction.  

#### Just Files

PNG->Wave (using binwalk) -> morse code (audacity spectrogram) -> reverse second half of the audio -> audio clip from lucifer -> steghide using password "lucifer" -> file with flag format

#### I Love You

deepsound on the wave -> welcome.exe -> used python-exe-unpacker -> decompyle -> get Iron man hint and flag format -> flag

#### Sharing is Caring

Standard Shamir's secret sharing problem, where we are given all n shares of the secret and the prime. There are many methods of solving it Z3, Matrix, Polynomial field with sage, etc. I used the gcd method to solve the polynomials. 
Reference: https://github.com/adviksinghania/shamir-secret-sharing/blob/main/shamir_secret_galois.py
