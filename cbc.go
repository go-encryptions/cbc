// Package cbc implements AES-CBC for disk encryption, with an arm64 kernel
// that decrypts 8 blocks at a time.
//
// CBC decryption is parallel: plaintext block i is D(C[i]) ^ C[i-1], and
// every C is known before the first block is decrypted. crypto/cipher's
// CBC decrypter on arm64 decrypts one block at a time through the
// cipher.Block interface, which leaves the AES units mostly idle; this
// package runs the AESD rounds of 8 blocks interleaved, with the round keys
// held in registers, and produces byte-identical output.
//
// Disk formats give every sector its own IV, derived by encrypting the
// sector's position: BitLocker's eboiv is AES_K(byte offset), LUKS's essiv
// is AES_{SHA-256(K)}(sector number). DecryptSectors takes one IV per
// sector, and EncryptECB computes a batch of such IVs 8 blocks at a time.
//
// Encryption is serial by nature (each block needs the previous ciphertext)
// and goes through crypto/cipher. Architectures other than arm64 use
// crypto/cipher throughout; the output is the same everywhere.
package cbc

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const blockSize = aes.BlockSize

// Cipher is an expanded AES key. It is safe for concurrent use.
type Cipher struct {
	b cipher.Block

	// accelerated reports whether the assembly kernels are used. It is
	// set on arm64; tests clear it to exercise the portable path there.
	accelerated bool
	enc, dec    []byte // flat round-key schedules for the kernels
	rounds      int
}

// NewCipher returns a Cipher for an AES key of 16, 24 or 32 bytes.
func NewCipher(key []byte) (*Cipher, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c := &Cipher{b: b}
	c.setupAccel(key)
	return c, nil
}

var errIV = errors.New("cbc: IV length must equal block size")

func checkBlocks(dst, src []byte) {
	if len(src)%blockSize != 0 {
		panic("cbc: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("cbc: output smaller than input")
	}
}

// Decrypt decrypts src into dst in CBC mode with iv, as
// cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, src) does. dst and
// src must overlap entirely or not at all; len(src) must be a multiple of
// 16 and len(iv) 16.
func (c *Cipher) Decrypt(dst, src, iv []byte) {
	checkBlocks(dst, src)
	if len(iv) != blockSize {
		panic(errIV)
	}
	if !c.decAccel(dst, src, iv) {
		cipher.NewCBCDecrypter(c.b, iv).CryptBlocks(dst[:len(src)], src)
	}
}

// DecryptSectors decrypts consecutive sectors of sectorSize bytes, sector i
// with the IV ivs[16*i:16*i+16]: each sector is its own CBC chain, as disk
// encryption lays them out. sectorSize must be a positive multiple of 16,
// len(src) a multiple of sectorSize and len(ivs) 16 per sector.
func (c *Cipher) DecryptSectors(dst, src []byte, sectorSize int, ivs []byte) {
	if sectorSize <= 0 || sectorSize%blockSize != 0 {
		panic("cbc: sector size is not a positive multiple of the block size")
	}
	if len(src)%sectorSize != 0 {
		panic("cbc: input is not a whole number of sectors")
	}
	if len(ivs) != blockSize*(len(src)/sectorSize) {
		panic("cbc: one 16-byte IV per sector")
	}
	checkBlocks(dst, src)
	for i, k := 0, 0; i < len(src); i, k = i+sectorSize, k+blockSize {
		c.Decrypt(dst[i:i+sectorSize], src[i:i+sectorSize], ivs[k:k+blockSize])
	}
}

// EncryptECB encrypts each 16-byte block of src into dst independently:
// the building block of per-sector IVs (eboiv, essiv), 8 blocks at a time
// on arm64.
func (c *Cipher) EncryptECB(dst, src []byte) {
	checkBlocks(dst, src)
	if !c.ecbAccel(dst, src) {
		for i := 0; i < len(src); i += blockSize {
			c.b.Encrypt(dst[i:i+blockSize], src[i:i+blockSize])
		}
	}
}

// Encrypt encrypts src into dst in CBC mode with iv, through crypto/cipher:
// each block needs the previous ciphertext, so one chain cannot be
// parallelised.
func (c *Cipher) Encrypt(dst, src, iv []byte) {
	checkBlocks(dst, src)
	if len(iv) != blockSize {
		panic(errIV)
	}
	cipher.NewCBCEncrypter(c.b, iv).CryptBlocks(dst[:len(src)], src)
}
