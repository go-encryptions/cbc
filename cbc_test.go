package cbc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/rand"
	"testing"
)

// lengths reach every path of the kernels: no block, the 1..7-block tail
// alone, one and several groups of 8, and groups followed by a tail.
var lengths = []int{0, 16, 32, 112, 128, 144, 240, 256, 400, 512, 4096}

func ciphers(t *testing.T, rng *rand.Rand) []*Cipher {
	t.Helper()
	var out []*Cipher
	for _, n := range []int{16, 24, 32} {
		key := make([]byte, n)
		rng.Read(key)
		for _, portable := range []bool{false, true} {
			c, err := NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			if portable {
				c.accelerated = false
			}
			out = append(out, c)
		}
	}
	return out
}

func name(c *Cipher, n int) string {
	return fmt.Sprintf("rounds%d/accelerated=%v/len%d", c.rounds, c.accelerated, n)
}

// TestDecryptMatchesStdlib: byte-identical to crypto/cipher's CBC
// decrypter, in place and not.
func TestDecryptMatchesStdlib(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, c := range ciphers(t, rng) {
		for _, n := range lengths {
			ct := make([]byte, n)
			rng.Read(ct)
			iv := make([]byte, 16)
			rng.Read(iv)
			want := make([]byte, n)
			cipher.NewCBCDecrypter(c.b, iv).CryptBlocks(want, ct)

			got := make([]byte, n)
			c.Decrypt(got, ct, iv)
			if !bytes.Equal(got, want) {
				t.Fatalf("%s: Decrypt differs from crypto/cipher", name(c, n))
			}
			inPlace := append([]byte(nil), ct...)
			c.Decrypt(inPlace, inPlace, iv)
			if !bytes.Equal(inPlace, want) {
				t.Fatalf("%s: Decrypt in place differs", name(c, n))
			}
			// round trip through Encrypt
			back := make([]byte, n)
			c.Encrypt(back, want, iv)
			if !bytes.Equal(back, ct) {
				t.Fatalf("%s: Encrypt does not invert Decrypt", name(c, n))
			}
		}
	}
}

// TestDecryptSectors: each sector is its own chain with its own IV.
func TestDecryptSectors(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for _, c := range ciphers(t, rng) {
		for _, ss := range []int{16, 512, 4096} {
			for _, n := range []int{0, 1, 3} {
				ct := make([]byte, ss*n)
				rng.Read(ct)
				ivs := make([]byte, 16*n)
				rng.Read(ivs)
				want := make([]byte, len(ct))
				for i := range n {
					cipher.NewCBCDecrypter(c.b, ivs[16*i:16*i+16]).CryptBlocks(want[i*ss:(i+1)*ss], ct[i*ss:(i+1)*ss])
				}
				got := make([]byte, len(ct))
				c.DecryptSectors(got, ct, ss, ivs)
				if !bytes.Equal(got, want) {
					t.Fatalf("%s/ss%d: DecryptSectors differs", name(c, len(ct)), ss)
				}
			}
		}
	}
}

// TestEncryptECB: every block encrypted alone, as cipher.Block does.
func TestEncryptECB(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for _, c := range ciphers(t, rng) {
		for _, n := range lengths {
			pt := make([]byte, n)
			rng.Read(pt)
			want := make([]byte, n)
			for i := 0; i < n; i += 16 {
				c.b.Encrypt(want[i:i+16], pt[i:i+16])
			}
			got := make([]byte, n)
			c.EncryptECB(got, pt)
			if !bytes.Equal(got, want) {
				t.Fatalf("%s: EncryptECB differs", name(c, n))
			}
			c.EncryptECB(pt, pt)
			if !bytes.Equal(pt, want) {
				t.Fatalf("%s: EncryptECB in place differs", name(c, n))
			}
		}
	}
}

func TestRefusals(t *testing.T) {
	if _, err := NewCipher(make([]byte, 5)); err == nil {
		t.Error("a 5-byte key accepted")
	}
	c, _ := NewCipher(make([]byte, 16))
	b16, b32, b8 := make([]byte, 16), make([]byte, 32), make([]byte, 8)
	for label, f := range map[string]func(){
		"partial block":  func() { c.Decrypt(b16, b8, b16) },
		"short output":   func() { c.Decrypt(b16, b32, b16) },
		"short IV":       func() { c.Decrypt(b16, b16, b8) },
		"encrypt IV":     func() { c.Encrypt(b16, b16, b8) },
		"ecb partial":    func() { c.EncryptECB(b16, b8) },
		"sector size 0":  func() { c.DecryptSectors(b32, b32, 0, b16) },
		"sector size 24": func() { c.DecryptSectors(b32, b32, 24, b16) },
		"partial sector": func() { c.DecryptSectors(b32, b32[:16], 32, b16) },
		"IV count":       func() { c.DecryptSectors(b32, b32, 16, b16) },
		"sectors output": func() { c.DecryptSectors(b16, b32, 16, b32) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", label)
				}
			}()
			f()
		}()
	}
}

// FuzzDecrypt compares the kernel with crypto/cipher on arbitrary input.
func FuzzDecrypt(f *testing.F) {
	f.Add(make([]byte, 16), make([]byte, 16), make([]byte, 144))
	f.Fuzz(func(t *testing.T, key, iv, ct []byte) {
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return
		}
		if len(iv) != 16 || len(ct)%16 != 0 || len(ct) > 1<<16 {
			return
		}
		c, err := NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := aes.NewCipher(key)
		want := make([]byte, len(ct))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(want, ct)
		got := make([]byte, len(ct))
		c.Decrypt(got, ct, iv)
		if !bytes.Equal(got, want) {
			t.Fatal("differs from crypto/cipher")
		}
	})
}
