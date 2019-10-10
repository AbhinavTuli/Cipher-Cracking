import sys
from BitVector import *

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

#take key from user
if sys.version_info[0]==3:
    key = input("\nEnter key: ").strip()
else:
    key = raw_input("\nEnter key: ").strip()

key_bv = BitVector(bitlist=[0]*BLOCKSIZE)

#convert key into BitVector
for i in range(len(key)//numbytes):
    keyblock = key[i*numbytes:(i+1)*numbytes]
    key_bv ^= BitVector(textstring=keyblock)

#initialize the BitVector that will store the message in binary form and initialize prev
recover_bv=BitVector(size=0)
prev=bv_iv

#maintain previous and then xor with previous and key, by the property of XOR we get back the original text
for i in range(len(ciphertext_bv)//BLOCKSIZE):
    bv_read=ciphertext_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
    q=bv_read
    bv_read=bv_read^key_bv^prev
    recover_bv+=bv_read
    prev=q

# print(len(recover_bv))
#convert the original text to a string from BitVector
recover = recover_bv.get_text_from_bitvector()

#write the recovered text to a file
FILEOUT = open(sys.argv[2],'w')
FILEOUT.write(recover)
FILEOUT.close()
