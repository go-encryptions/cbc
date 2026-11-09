//go:build !arm64

package cbc

// No assembly kernel on this architecture: crypto/cipher does the work.

func (c *Cipher) setupAccel(key []byte) {}

func (c *Cipher) decAccel(dst, src, iv []byte) bool { return false }

func (c *Cipher) ecbAccel(dst, src []byte) bool { return false }
