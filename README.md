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

On one Apple M4 Max core, decryption runs at about the speed of OpenSSL
3.6.5 (`openssl speed -decrypt -evp aes-128-cbc`) and about 8× faster than
`crypto/cipher`, with zero allocations. The table measured under a load
below 8 is in the first pull request (#1). `BenchmarkDecrypt`,
`BenchmarkStdlib` and `BenchmarkDecryptSectors` reproduce it.

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
