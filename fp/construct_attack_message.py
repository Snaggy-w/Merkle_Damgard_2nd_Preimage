import sys

ms           = bytes.fromhex('1ee79068d30e411f50c13b7431b8eb94')
mf           = bytes.fromhex('5e2db72e754e1a1e84d48225615b92d3')
ml           = bytes.fromhex('cd16916a9af5e4b1a027989709a67a00')
k            = 25823620
suffix_zeros = 3881789344

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
