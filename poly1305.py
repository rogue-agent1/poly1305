#!/usr/bin/env python3
"""poly1305 - Poly1305 message authentication code."""
import sys, struct

def poly1305_mac(key, msg):
    r = int.from_bytes(key[:16], 'little')
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:32], 'little')
    acc = 0
    p = (1 << 130) - 5
    for i in range(0, len(msg), 16):
        chunk = msg[i:i+16]
        n = int.from_bytes(chunk, 'little') + (1 << (8 * len(chunk)))
        acc = ((acc + n) * r) % p
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, 'little')

def main():
    print("Poly1305 MAC demo\n")
    key = bytes(range(32))
    msg = b"Cryptographic primitives are fun!"
    tag = poly1305_mac(key, msg)
    print(f"  Message: {msg.decode()}")
    print(f"  Key:     {key.hex()[:32]}...")
    print(f"  Tag:     {tag.hex()}")
    # Verify
    tag2 = poly1305_mac(key, msg)
    print(f"  Verify:  {'✓' if tag == tag2 else '✗'}")
    # Tampered
    tampered = bytearray(msg); tampered[0] ^= 1
    tag3 = poly1305_mac(key, bytes(tampered))
    print(f"  Tampered: {'✗ (different)' if tag != tag3 else '✓ (same — bad!)'}")
    # RFC 7539 test
    key_tv = bytes([0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
                    0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b])
    msg_tv = b"Cryptographic Forum Research Group"
    tag_tv = poly1305_mac(key_tv, msg_tv)
    print(f"\n  RFC test tag: {tag_tv.hex()}")

if __name__ == "__main__":
    main()
