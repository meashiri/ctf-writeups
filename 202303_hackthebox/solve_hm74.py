
'''
Mechanics of the Hamming(7,4)

The goal of Hamming codes is to create a set of parity bits that overlap such that a single-bit error (one bit is flipped) in a data bit or a parity bit can be detected and corrected. Only if there occur multiple errors, the Hamming code fails of recovering the original data. It may not notice an error at all, or even correct it falsely. Therefore in this challenge we will only deal with single-bit errors.

As an example of the Hamming codes, we will look at the Hamming(7,4) code. Additionally to 4 bits of data d1, d2, d3, d4 it uses 3 parity bits p1, p2, p3, which are calculated using the following equations:

p1 = (d1 + d2 + d4) % 2
p2 = (d1 + d3 + d4) % 2
p3 = (d2 + d3 + d4) % 2

The resulting codeword (data + parity bits) is of the form p1 p2 d1 p3 d2 d3 d4.

Detecting an error works the following way. You recalculate the parity bits, and check if they match the received parity bits. In the following table you can see, that every variety of a single-bit error yields a different matching of the parity bits. Therefore every single-bit error can be localized and corrected.

==> p0 p1 d3 p2 d2 d1 d0

error in bit | p0 | p1 | d3 | p2 | d2 | d1 | d0 | no error
-------------|---------------------------------------------
p0 matches   | no | yes| no | yes| no | yes| no | yes
p1 matches   | yes| no | no | yes| yes| no | no | yes
p2 matches   | yes| yes| yes| no | no | no | no | yes

assign p0 = data_in[3] ^ data_in[2] ^ data_in[0]; 
assign p1 = data_in[3] ^ data_in[1] ^ data_in[0];
assign p2 = data_in[2] ^ data_in[1] ^ data_in[0];

assign ham_out = {p0, p1, data_in[3], p2, data_in[2], data_in[1], data_in[0]};

'''
import string

def extractParityData(bs):
    parity = (
        int(bs[0]), 
        int(bs[1]),
        int(bs[3])
    )

    data = [
        int(bs[6]),
        int(bs[5]),
        int(bs[4]),
        int(bs[2])
    ]
    return( (parity, data) )

def getErrorIndex(P1, P2):

    errors = []
    if (P1[2] != P2[2] and P1[1] != P2[1] and P1[0] != P2[0] ):
        errors.append(0)
    elif (P1[2] != P2[2] and P1[1] != P2[1] and P1[0] == P2[0] ):
        errors.append(1)
    elif (P1[2] != P2[2] and P1[1] == P2[1] and P1[0] != P2[0] ):
        errors.append(2)
    elif (P1[2] == P2[2] and P1[1] != P2[1] and P1[0] != P2[0] ):
        errors.append(3)    
    return errors

def calculateParity(data):
    parity = (
        data[3] ^ data[2] ^ data[0],
        data[3] ^ data[1] ^ data[0],
        data[2] ^ data[1] ^ data[0]
    )
    return parity

def get_corrected_bits(bs):
    P,D = extractParityData(bs)
    Pcalc = calculateParity(D)
#    print(f"{bs=} : {P=} : {Pcalc=}  | {D=}")

    if (Pcalc == P):
#        print(f"{bs} : no errors")
        return D
    else: 
        errors = getErrorIndex(P,Pcalc)
        for i in errors:
            D[i] = ( D[i]+1 )%2  # flip the bit
#        print(f"{bs} : {errors} : {D}")
        return D

# 01001000 01010100 01000010 01111011

freq=[] # a list of dictionaries for each position
for i in range(68):
    freq.append( {} )

if __name__ == "__main__":
    with open("hamming_data.txt", "r") as f:
        for l in f:
            fc = ""
            b=""
            di = 0 # index 
            a = l.split(':')[1].strip()
            for i in range(0, len(a), 7):
                nibble = ''.join(str(x) for x in get_corrected_bits(a[i:i+7]))
                b+=nibble[::-1]
                if (len(b) == 8):
                    c = chr(int(b,2))
                    if c.isprintable():
                        fc += c
                        if c in freq[di].keys():
                            freq[di][c] = freq[di][c] + 1
                        else:
                            freq[di][c] = 1 
                    else:
                        # ignore - not printable
                        fc += " "
                    di+=1
                    b = ""
            print(fc)
        f.close()

    print("\n\n")
    flag = ""
        
    for d in freq:
        flag+=max(d, key=d.get) # Get the most frequently occurring character in each position

    print(flag) 



'''
HTB{hmm_w1                                                             
]`Bw`mo¶µ1`o[30m3\enaáy}`8ÝyppRf`n_`}eâanw_7ø3_`0kCjjä_7`1W·`c_ál4;A
HôB{a½3`záDh_sp`:/aùca|Ó15_s0u]cZn'Tx7rq}D`7`0_³4mm`c9U§Ï´_5Î`_e`q<`
HfO`jm~_w4thTs`m3WÑ>á1qvq5_y0|_s´`[?x7â±hq[;h`Sh5½m`Î`o·o4_3*c¹V¬:7}
Ø`B`him_w1t`[`6=?Wa2o1{sa5_u3%[c7nÁóhppaft_:e3V`3m``>?_7V¿`3Ìc¿`üb<}
AUH{hmM`{ñô(Qs0`3¿anb9ézñ5Vù`._S4î_:xß6aft]7hKRh,mm)m9V7ï4Ö``@Ïdl=I}
HZB{(cmÿw1thÏ`°m?Qa^`5yz8`ß}`eVc`n``È2rr3ä_òjºV¨1omb~0_7Q4Z3nc_flä=M
EDN{èem¿w!ta_s0m1_Aka1ys;5_s0u]c¤n_3è§Bac~_`e3_e¤mm9¾9_?O4_3nï`m`4¹`
HRA{`nm_÷1th\z0m`ßafñ1yw95`É0uºc``]Ñx`2act_6hs_H4mGin8[7Y4I0bgWÖit`-
A´r|h½m[`ºth_sp``S1na8yy±9_Y0)_c`n¿3x`r`ctV7k#`È`ímk`9_7_gç`ncofï49}
HT`uXmm`§?whZ§<m`_%`a`9u1eÕy2/OS4n[5a'rló__7dãßhô-fin9_6_9QcnC_fì4ù}
FTBëjímQy1üa_``Í8_c>a<è¡55_ypu_c3`_wx7qqcp_5h3_`4`mgn4Z7_gß3nf_öa`9}
ET@`oh-/w1w`_³>G£ZÏ^aÑy&1?[y25_bÐnÏ`µ=¼ccd`6h3`Ú4md`n`/7_ä_`n`ÿa|4¹|
HVB`e}m[w!pþ`x0m3fanQ1ys0Ñ_`6%_ct`\CpW¢`cr`7m`/`´]`kn9]7`7V3Þi]fj`»i
HT`{`mm\¶?tqos7x3^b¹a`ys2µW}Ðu_h`Þ`3x7`am`]gèö[`²mjij`_§`<\³mjWÆh`Ñí
hôF{ømm_t¡tÜgs4m3Zana1å#1=ÇI<u[£1n_`(·§Hgt`7dz_`8cm)f9``]4`3lmVheÿ9`
`´`{jým_Õ1th`ó0m=_anaãys1`Ïy4÷_3¤n_3r7rfcpX7h3_(?m`i.9T§ßt]3ìjQfl4)-
D`Â{e@M_~1sh`Spm`_oed=)s1µ`yÐuRaÔO_3(7tAcä¿'hC_84]jic`_/_T`3nc`meÜ9t
^ôB»hmm[w1thXs5n£`a`!aysq5_x`u_cnÎ_`xO|f`tXa`=ß9`mx`k¡^7/¤S`kb_`l<9Ý
ÈVAxh.mOw1$`_;8f7ÚhnÁ`{säõ_Á@u_i©nT3+7rac4]?hÒ?`ômmin9_7`4W3nóëf`40u
NVB{amí/§5t8_s0á5_QPQ1``?=_z5xÏ#´n\0xw`a`tU7h`Xh`mmim0ÿ`Q2Ü3dãxfo04m
HVG{X7mÚw`tlÏ#9)³RalQ1yç95Hy0H`c4n_3x7ra`t_×j3Rh:m`In9`7_4o3ncXfl49ý
AT`{`mmWw1th_s0m3R`n`2us15_|0u_c´.O=x:y`m~V7hS_õ=lmÉnY_7Ã4S5n`Áfl4,{
FRB`hmm_w1}h_s0a`!ön`1és15_ykUQj$H¼3z7Q1mä_¹{9_Ø0`mÉn9/`Ï4V;n°^fl4yC
øTBÛ-mm_w1}``s`c=_a`aÕxs1=Z~0`_c4n`:r9¸áÃtÏ7hS`øßmmkþ=_wo`_9îº_eb`9}
mQLéhÝm_`24¸ßsÐi?oA¢a¬p}<`_q0q»ã`kD:q·saSpR7j£=hÔmmin`_7j4_3þe`fm0©}
`QBÛxmh_g1t(Ãã2eê_a`a5qó15op3uï*D._`È?rbaw_wh=_8¤.llnI`9`4`£nã`flD)}
A4Ivømm`~8ôh_wÐm6_ane¡)s10}|0Eïc4`_`x7ra#t_7h3_f4Mmi2iY9¿ôÏ3`c_h<49`
Hdò``mm¿w¡$i=`4=3_aSa1iv65`y0î_ç4n_sx``aÃu}§o`_`Dmmy`9_ç_'_º=SS¶dtm}
DTBym=mQ×3thQr0m3Ïá¾g!}s11>u2vVc4n`3x7r¡ctY7e``h4hok0Ù_5Ê4W7n`_fe<¸-
`TB}ldm_t1zh_s0¯3_Dn`5¹#Q<_y1|Ta4f_1x7Àaæ`_4Û×\i¤`min9Z÷_}_3n`_`iä9x
HT`;8mmYwqlh_q0o3_ana=ys9EQ¹6e_j4ýf3x9ract`9h3\h0moÛm0ï7S0_:îj_6l¼:}
EVB{fÍm_`±dh_s0mC^aka?ts14`yÖu`ó2>ß`v7vacWï7h;¿f?Amin9Y9Ì´ï3``_al4m}
hgY»hhÝ_ÇÑtX`s0m£_d¾5%}s1`_ñÙu_c4 _ªx3rbh4_5h7_hÔ>=)g9k7S`_ãn1`dl49L
@T`,Èmk]ýµÔh_w9ms_QnA2ysA5_w0u½cÚ.¿9{Wvigt_7h#_ø9mmcå9Z2o9_r^Í_f,>9`
MTB{Hní^w1dhO³r-6_a^!1ys15Yy°áoS5m_=x0p`cqï7h3_h`dMÙb9ÁG_`_?]c_ðü4©ý
`ÔBëhM¬lw±Ìo_s0=1¿a¾a1w`54_ù``V`ñ¾_3¸78ac`_9ø`nh=`]in:W4_´_`nê_%e47}
¨TB{hmm_F1t8_}è`3ÿaeá1`×±çßy0u_C?`O=x7ricpW7fà_h¤Ù``^`*7Æt`3n#gfj49Þ
LT@{è³m`ç`4h_zmm4[ln``usÑ5?yÐu_34n_3`7rac437m1ß`0om`n`º7ï4¿ã^c_&l4ù}
H`L»ømm]w5Th_u2m][!ÎaÑ@sQ5`yp}_c4n_3x1ract¸`hS`aami`n`Vg_4`3`Ó]f|¢^-

'''
