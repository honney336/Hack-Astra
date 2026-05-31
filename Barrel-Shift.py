
def solve():
    ckdata = [
        0x83, 0xc3, 0x65, 0xa6, 0x28, 0xd2, 0x0b, 0xed, 
        0x95, 0xd6, 0xaa, 0x10, 0x39, 0x92, 0xae, 0x75, 
        0x35, 0xb1, 0x99, 0xf8, 0x9a, 0xf9
    ]

    flag = ""
    for i in range(22):
        # Reverse the addition of the index 'i'
        target = (ckdata[i] - i) & 0xff
        
        # Reverse the 8-bit right rotation by 3 -> Left rotate by 3
        c_xor = ((target << 3) & 0xff) | ((target >> 5) & 0xff)
        
        # Reverse the XOR with 0x5a
        c = c_xor ^ 0x5a
        
        flag += chr(c)

    print("[+] Recovered Flag:", flag)

if __name__ == "__main__":
    solve()

