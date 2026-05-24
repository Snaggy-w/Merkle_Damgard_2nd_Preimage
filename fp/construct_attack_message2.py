import sys

ms           = bytes.fromhex('9419fd96e51fb806a706ea4c28a78e4d')
mf           = bytes.fromhex('404b6e0d1902f610d6472222ef12f342')
ml           = bytes.fromhex('b89870f0bc100a628957b329edb8024b')
k            = 114313876
suffix_zeros = 2465945248

out = sys.stdout.buffer

out.write(ms)

# Write mf repeated k times in large chunks.
if k > 0:
    REPS = max(1, 65536 // len(mf))  # ~4096 for BLEN=16
    chunk = mf * REPS
    full, rem = divmod(k, REPS)
    for _ in range(full):
        out.write(chunk)
    if rem:
        out.write(mf * rem)

out.write(ml)

# Zero suffix (original message was all zeros).
if suffix_zeros > 0:
    CHUNK = 1 << 16  # 64 KB
    buf   = bytearray(CHUNK)
    left  = suffix_zeros
    while left > 0:
        n = min(CHUNK, left)
        out.write(memoryview(buf)[:n])
        left -= n
