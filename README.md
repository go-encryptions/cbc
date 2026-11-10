# cbc

AES-CBC for disk encryption in pure Go, with an arm64 kernel that decrypts
8 blocks at a time. Output is byte-identical to `crypto/cipher`.

```go
c, err := cbc.NewCipher(key) // 16, 24 or 32 bytes

c.Decrypt(dst, src, iv)                   // one CBC chain
c.DecryptSectors(dst, src, 512, ivs)      // one chain per sector, one IV each
c.EncryptECB(ivs, positions)              // per-sector IVs: eboiv, essiv
c.Encrypt(dst, src, iv)                   // through crypto/cipher (serial)
```

## Why

CBC decryption is parallel. Each plaintext block is `D(C[i]) ^ C[i-1]`, and
every ciphertext block is known before the first one is decrypted.
`crypto/cipher`'s CBC decrypter does not exploit that on arm64:
- it decrypts one block at a time through the `cipher.Block` interface;
- it allocates a 512-byte buffer per call.

This package interleaves the AESD rounds of 8 blocks and keeps every round
key in a register, the same kernel shape as
[go-encryptions/xts](https://github.com/go-encryptions/xts).

Disk formats give each sector its own IV by encrypting its position:
- BitLocker's eboiv is `AES_K(byte offset)`;
- LUKS's essiv is `AES_{SHA-256(K)}(sector)`.

`EncryptECB` computes those IVs 8 at a time, and `DecryptSectors` takes one
IV per sector.

Encryption cannot be parallelised within one chain, because each block
needs the previous ciphertext. `Encrypt` therefore uses `crypto/cipher`.

On architectures other than arm64, everything goes through `crypto/cipher`.
The output is the same everywhere.

## Measured

Decryption on one Apple M4 Max core. The figures come from
`abbench --max-load 8`: 6 interleaved rounds against `crypto/cipher`'s CBC
decrypter. The reference is OpenSSL 3.6.5 on the same core
(`openssl speed -decrypt -evp aes-*-cbc -bytes N`):

| | `crypto/cipher` | this package | OpenSSL |
|---|---|---|---|
| AES-128, 512 B | 2.03 GB/s | **18.3 GB/s** (104 %) | 17.6 GB/s |
| AES-128, 4 KiB | 2.59 GB/s | **20.7 GB/s** (101 %) | 20.6 GB/s |
| AES-256, 512 B | 1.92 GB/s | **14.8 GB/s** (107 %) | 13.8 GB/s |
| AES-256, 4 KiB | 2.48 GB/s | **15.3 GB/s** (118 %) | 13.0 GB/s |

This package makes zero allocations per call; `crypto/cipher` makes one
(512 bytes). `BenchmarkDecrypt` and `BenchmarkStdlib` reproduce the table.

## Checked

- Every path is compared block for block with `crypto/cipher`: AES-128,
  -192 and -256; the 8-block groups and the 1–7 block tail; in place or
  not; the kernel and the portable path.
- `FuzzDecrypt` does the same on arbitrary input.
- Two deliberate breaks of the assembly, one per kernel, each failed the
  tests.
- CI runs on amd64, arm64, riscv64, loong64, ppc64le and big-endian s390x,
  with 100 % coverage on each.

The AES key schedules are a copy of go-encryptions/xts's, until both use
one shared package.

## Licence

BSD-3-Clause.
