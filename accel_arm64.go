//go:build arm64

package cbc

// The Go runtime requires the ARMv8 AES instructions on arm64, so the
// kernels need no feature probe.

func (c *Cipher) setupAccel(key []byte) {
	c.enc = expandEnc(key)
	c.dec = expandDec(key)
	c.rounds = len(key)/4 + 6
	c.accelerated = true
}

// decAccel decrypts with cbcDecAsm. The IV is copied to the stack, which
// the noescape kernel reads without a heap allocation.
func (c *Cipher) decAccel(dst, src, iv []byte) bool {
	if !c.accelerated {
		return false
	}
	if len(src) == 0 {
		return true
	}
	if &dst[0] != &src[0] {
		copy(dst, src)
	}
	var v [blockSize]byte
	copy(v[:], iv)
	cbcDecAsm(dst[:len(src)], &c.dec[0], c.rounds, &v[0])
	return true
}

func (c *Cipher) ecbAccel(dst, src []byte) bool {
	if !c.accelerated {
		return false
	}
	if len(src) == 0 {
		return true
	}
	if &dst[0] != &src[0] {
		copy(dst, src)
	}
	ecbEncAsm(dst[:len(src)], &c.enc[0], c.rounds)
	return true
}

// cbcDecAsm decrypts p in place (a non-zero multiple of 16 bytes) in CBC
// mode: dec is expandDec's schedule, iv the 16-byte IV.
//
//go:noescape
func cbcDecAsm(p []byte, dec *byte, rounds int, iv *byte)

// ecbEncAsm encrypts every block of p in place with expandEnc's schedule.
//
//go:noescape
func ecbEncAsm(p []byte, enc *byte, rounds int)
