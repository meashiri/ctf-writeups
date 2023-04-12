import string

disp = [
    0x56, 0x0b, 0x0b, 0x13, 0x15, 0x0b, 
    0x01, 0x1f, 0x0d, 0x13, 0x0d, 0x0b, 
    0x15, 0x16, 0x0b, 0x29, 0x0d, 0x1f, 
    0x02, 0x1f, 0x0b, 0x1f, 0x29, 0x18,
    0x0d, 0x01, 0x15, 0x1f, 0x15, 0x0b, 
    0x15, 0x0d, 0x1f, 0x40, 0x27, 0x0b,
    0x45, 0x29
]

# found in myxor.v
key = 0x0d 

#    :.65.3..0
#  SW:0,3,5,6 from the trace images
sw = [
    [1,1,1,1],
    [0,0,1,0],
    [1,0,1,1],
    [1,0,1,1],
    [0,0,1,1],
    [0,0,1,0],
    [0,0,1,0],
    [1,0,1,1],
    [0,0,1,0],
    [1,0,1,1],  #10
    [0,0,1,0],
    [0,0,1,0],
    [0,1,1,0],
    [1,1,1,0],
    [0,0,1,0],
    [0,0,1,1],
    [0,0,1,0],
    [1,0,1,1],  #18-0x12
    [1,0,1,0],
    [1,0,1,1],
    [0,0,1,0],
    [0,0,1,0],
    [0,0,1,1],
    [1,0,1,0],
    [0,0,1,0],
    [0,0,1,0],
    [0,1,1,0],  #27-0x1b
    [0,0,1,0],
    [0,0,1,1],
    [0,0,1,0],
    [0,1,1,0],
    [0,0,1,0],
    [0,0,1,0],
    [1,1,1,1],
    [1,0,1,1],
    [1,0,1,1],  #36-0x24
    [0,1,1,1],
    [0,0,1,1],
]

allowed_chars = string.digits + "abcdeflg{}"

#dictionary of all 4-bit x 4-bit products
D = {}
for a in range(16):
    for b in range(16):
        p = a*b
        print(f"{a:04b} x {b:04b} = {p:08b}  [{p:3d}]")

        if (p not in D):
            D[p] = []
        D[p].append((a,b))

S = ''
for i,x in enumerate(disp):
    m = x ^ key

    if (m in D):
        for f,s in D[m]:
            ans = f*16 + s
            # convert to binary string and reverse it so that lsb is at [0] and msb is at [7]
            bans = "{:08b}".format(ans)[::-1]

            if (int(bans[0]) == sw[i][0]
                and 
                int(bans[3]) == sw[i][1]
                and 
                int(bans[5]) == sw[i][2]
                and
                int(bans[6]) == sw[i][3]):
                
                fc = chr(ans)
                if (fc in allowed_chars):
                    print (f"[{i:2d}] Found in [{len(D[m]):2d}] options: {m:02x} {m:03d} {f:04b} {s:04b} {ans:3d} {fc}")
                    S+=fc

#since the original flag is processed in the reverse order, reverse the assembled flag 
print(S[::-1])
