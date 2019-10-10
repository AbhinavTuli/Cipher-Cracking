import sys
from BitVector import *
from collections import defaultdict
import string
if len(sys.argv) is not 3:
    sys.exit()

PassPhrase="I want to learn cryptograph and network security"

BLOCKSIZE=64
numbytes=BLOCKSIZE//8

#convert passphrase into a BitVector
bv_iv = BitVector(bitlist=[0]*BLOCKSIZE)
for i in range(len(PassPhrase)//numbytes):
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]
    bv_iv ^= BitVector( textstring = textstr )

#read the ciphertext and convert it into BitVector
FILEIN = open(sys.argv[1])
ciphertext_bv = BitVector(hexstring=FILEIN.read())

prev=bv_iv


d0=defaultdict(int)
d1=defaultdict(int)
d2=defaultdict(int)
d3=defaultdict(int)
d4=defaultdict(int)
d5=defaultdict(int)
d6=defaultdict(int)
d7=defaultdict(int)

#maintain previous and then xor with previous and key, by the property of XOR we get back the original text
for i in range(len(ciphertext_bv)//BLOCKSIZE):
    bv_read=ciphertext_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
    q=bv_read
    bv_read=bv_read^prev
    prev=q
    #recover_bv+=bv_read
    st=bv_read.get_text_from_bitvector()
    d0[st[0]]+=1
    d1[st[1]]+=1
    d2[st[2]]+=1
    d3[st[3]]+=1
    d4[st[4]]+=1
    d5[st[5]]+=1
    d6[st[6]]+=1
    d7[st[7]]+=1

a0=str(max(d0, key=d0.get))
a1=str(max(d1, key=d1.get))
a2=str(max(d2, key=d2.get))
a3=str(max(d3, key=d3.get))
a4=str(max(d4, key=d4.get))
a5=str(max(d5, key=d5.get))
a6=str(max(d6, key=d6.get))
a7=str(max(d7, key=d7.get))

l1=list(string.printable)
# print(l1)
t=0
s="etaoinsrhdlucmfywgpbvkxqjz "
while t<27:
    b0=s[t]
    f0=ord(b0)
    e0=ord(a0)
    k0=f0^e0
    for i in range(len(ciphertext_bv)//BLOCKSIZE):
        f=0
        bv_read=ciphertext_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        q=bv_read
        bv_read=bv_read^prev
    #recover_bv+=bv_read
        st=bv_read.get_text_from_bitvector()
        if chr(k0^ord(st[0])) not in l1:
            f=-1
            break
    if f==0:
        break
    t=t+1

t=0
while t<27:
    b1=s[t]
    f1=ord(b1)
    e1=ord(a1)
    k1=f1^e1
    for i in range(len(ciphertext_bv)//BLOCKSIZE):
        f=0
        bv_read=ciphertext_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        q=bv_read
        bv_read=bv_read^prev
    #recover_bv+=bv_read
        st=bv_read.get_text_from_bitvector()
        if chr(k1^ord(st[1])) not in l1:
            f=-1
            break
    if f==0:
        break
    t=t+1


t=0
while t<27:
    b2=s[t]
    f2=ord(b2)
    e2=ord(a2)
    k2=f2^e2
    for i in range(len(ciphertext_bv)//BLOCKSIZE):
        f=0
        bv_read=ciphertext_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        q=bv_read
        bv_read=bv_read^prev
    #recover_bv+=bv_read
        st=bv_read.get_text_from_bitvector()
        if chr(k2^ord(st[2])) not in l1:
            f=-1
            break
    if f==0:
        break
    t=t+1

t=0

while t<27:
    b3=s[t]
    f3=ord(b3)
    e3=ord(a3)
    k3=f3^e3
    for i in range(len(ciphertext_bv)//BLOCKSIZE):
        f=0
        bv_read=ciphertext_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        q=bv_read
        bv_read=bv_read^prev
    #recover_bv+=bv_read
        st=bv_read.get_text_from_bitvector()
        if chr(k3^ord(st[3])) not in l1:
            f=-1
            break
    if f==0:
        break
    t=t+1


t=0

while t<27:
    b4=s[t]
    f4=ord(b4)
    e4=ord(a4)
    k4=f4^e4
    for i in range(len(ciphertext_bv)//BLOCKSIZE):
        f=0
        bv_read=ciphertext_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        q=bv_read
        bv_read=bv_read^prev
    #recover_bv+=bv_read
        st=bv_read.get_text_from_bitvector()
        if chr(k4^ord(st[4])) not in l1:
            f=-1
            break
    if f==0:
        break
    t=t+1


t=0

while t<27:
    b5=s[t]
    f5=ord(b5)
    e5=ord(a5)
    k5=f5^e5
    for i in range(len(ciphertext_bv)//BLOCKSIZE):
        f=0
        bv_read=ciphertext_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        q=bv_read
        bv_read=bv_read^prev
    #recover_bv+=bv_read
        st=bv_read.get_text_from_bitvector()
        if chr(k5^ord(st[5])) not in l1:
            f=-1
            break
    if f==0:
        break
    t=t+1


t=0

while t<27:
    b6=s[t]
    f6=ord(b6)
    e6=ord(a6)
    k6=f6^e6
    for i in range(len(ciphertext_bv)//BLOCKSIZE):
        f=0
        bv_read=ciphertext_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        q=bv_read
        bv_read=bv_read^prev
    #recover_bv+=bv_read
        st=bv_read.get_text_from_bitvector()
        if chr(k6^ord(st[6])) not in l1:
            f=-1
            break
    if f==0:
        break
    t=t+1


t=0
while t<27:
    b7=s[t]
    f7=ord(b7)
    e7=ord(a7)
    k7=f7^e7
    for i in range(len(ciphertext_bv)//BLOCKSIZE):
        f=0
        bv_read=ciphertext_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        q=bv_read
        bv_read=bv_read^prev
    #recover_bv+=bv_read
        st=bv_read.get_text_from_bitvector()
        if chr(k7^ord(st[7])) not in l1:
            f=-1
            break
    if f==0:
        break
    t=t+1

y0=chr(k0)
y1=chr(k1)
y2=chr(k2)
y3=chr(k3)
y4=chr(k4)
y5=chr(k5)
y6=chr(k6)
y7=chr(k7)

key=y0+y1+y2+y3+y4+y5+y6+y7
#print(key)
key_bv = BitVector(textstring=key)

recover_bv=BitVector(size=0)
prev2=bv_iv

for i in range(len(ciphertext_bv)//BLOCKSIZE):
    bv_read=ciphertext_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
    q=bv_read
    bv_read=bv_read^key_bv^prev2
    recover_bv+=bv_read
    prev2=q

# print(len(recover_bv))
#convert the original text to a string from BitVector
recover = recover_bv.get_text_from_bitvector()

#write the recovered text to a file
FILEOUT = open(sys.argv[2],'w')
FILEOUT.write(recover)
FILEOUT.close()
