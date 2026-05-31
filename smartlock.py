#!/usr/bin/env python3
import hashlib, hmac, json, sys
from pwn import remote

p = int(
    "db31bb574ef7a910671b6ef12198b6529371134114ac5a6a8c74388059e1d6d"
    "74d752e95b6c14d882342d8121349135d332af88b483ae8d8112141358d57dc"
    "e46980840ba94775378c9cce6bbd3fa76d9d92ffe61ca5f10c6848019cfef9"
    "c6b7a912e4dd55fcc279146a067f28510d2bbb568b1e2d516df29192ee54b02"
    "acd8b", 16)
q = int(
    "c1dfb94320225df97076076a445ec1cdd60a731b61ef2ad94e75c42e8525fabd", 16)
g = int(
    "6b44ae1b87a580892c5c08433591cf69fc07217772e61986c79442529918201"
    "28bb9c42f8cbeb6fd71f1054b0bd190a1444e990352897f9227516ae09afd60"
    "a5f397efd3ccd748d6b99c0242a16860819952409fc449dd1ad94839cdfd50"
    "6f72d314c0c02bb480d3d609ad64ecf0bf85cb7c3c68402156d15cede9368"
    "cb65896", 16)
key_size = (q.bit_length() + 7) // 8

def hval(data):
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % q

def badge_code(ticket):
    return hval(("badge-seed:" + ticket).encode()) or 1

io = remote(sys.argv[1], int(sys.argv[2]))
io.recvuntil(b"> ")

io.sendline(b"badge")
io.recvuntil(b"name: ")
io.sendline(b"solver")
badge = json.loads(io.recvline().decode().strip())

k      = badge_code(badge["ticket"])
h      = hval(badge["msg"].encode())
r, s   = int(badge["r"], 16), int(badge["s"], 16)
secret = (s * k - h) * pow(r, -1, q) % q

io.recvuntil(b"> ")
io.sendline(b"unlock")
nonce = bytes.fromhex(io.recvline().decode().strip().split("nonce: ")[1])

seal = hmac.new(secret.to_bytes(key_size, "big"),
                b"unlock:" + nonce, hashlib.sha256).hexdigest()

io.recvuntil(b"seal: ")
io.sendline(seal.encode())
print(json.loads(io.recvline())["flag"])
