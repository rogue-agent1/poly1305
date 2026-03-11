#!/usr/bin/env python3
"""Poly1305 message authentication code — pure Python."""
import struct, sys

def clamp(r):
    return r & 0x0ffffffc0ffffffc0ffffffc0fffffff

def poly1305_mac(msg, key):
    r = clamp(int.from_bytes(key[:16], 'little'))
    s = int.from_bytes(key[16:], 'little')
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i:i+16]
        n = int.from_bytes(chunk, 'little') + (1 << (8 * len(chunk)))
        acc = ((acc + n) * r) % p
    acc = (acc + s) % (1 << 128)
    return acc.to_bytes(16, 'little')

if __name__ == "__main__":
    key = bytes(range(32))
    msg = b"Cryptographic MAC test message for Poly1305"
    tag = poly1305_mac(msg, key)
    print(f"Message: {msg}")
    print(f"Tag:     {tag.hex()}")
    tag2 = poly1305_mac(msg, key)
    print(f"Verify:  {tag == tag2}")
    tag3 = poly1305_mac(msg + b"x", key)
    print(f"Tamper:  {tag == tag3}")
