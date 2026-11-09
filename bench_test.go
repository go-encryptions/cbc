package cbc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"testing"
)

// The reference is OpenSSL on the same core:
// `openssl speed -seconds 2 -bytes 4096 -decrypt -evp aes-128-cbc`.
// BenchmarkStdlib is crypto/cipher's CBC decrypter, what callers used.

func BenchmarkDecrypt(b *testing.B) {
	for _, keyLen := range []int{16, 32} {
		for _, n := range []int{512, 4096} {
			b.Run(fmt.Sprintf("AES-%d/%d", keyLen*8, n), func(b *testing.B) {
				c, _ := NewCipher(bytes.Repeat([]byte{7}, keyLen))
				buf, iv := make([]byte, n), make([]byte, 16)
				b.SetBytes(int64(n))
				b.ReportAllocs()
				for b.Loop() {
					c.Decrypt(buf, buf, iv)
				}
			})
		}
	}
}

func BenchmarkStdlib(b *testing.B) {
	for _, keyLen := range []int{16, 32} {
		for _, n := range []int{512, 4096} {
			b.Run(fmt.Sprintf("AES-%d/%d", keyLen*8, n), func(b *testing.B) {
				block, _ := aes.NewCipher(bytes.Repeat([]byte{7}, keyLen))
				buf, iv := make([]byte, n), make([]byte, 16)
				b.SetBytes(int64(n))
				b.ReportAllocs()
				for b.Loop() {
					cipher.NewCBCDecrypter(block, iv).CryptBlocks(buf, buf)
				}
			})
		}
	}
}

// BenchmarkDecryptSectors is a disk read: 1 MiB of 512-byte sectors, one
// IV each, the IVs computed by EncryptECB as eboiv does.
func BenchmarkDecryptSectors(b *testing.B) {
	c, _ := NewCipher(bytes.Repeat([]byte{7}, 16))
	buf, ivs := make([]byte, 1<<20), make([]byte, 16*2048)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	for b.Loop() {
		c.EncryptECB(ivs, ivs)
		c.DecryptSectors(buf, buf, 512, ivs)
	}
}
