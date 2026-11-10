//go:build arm64

#include "textflag.h"

// Both kernels hold every round key in a register for the whole call,
// aligned on the LAST key as in go-encryptions/xts: the final key is V30
// and the penultimate V29, so AES-128 uses V20..V30, AES-192 V18..V30 and
// AES-256 V16..V30, and the three key sizes enter one unrolled sequence of
// rounds at different points. Data is V0..V7.

#define keys14 \
	VLD1.P	64(R8), [V16.B16, V17.B16, V18.B16, V19.B16]; \
	VLD1.P	64(R8), [V20.B16, V21.B16, V22.B16, V23.B16]; \
	VLD1.P	64(R8), [V24.B16, V25.B16, V26.B16, V27.B16]; \
	VLD1	(R8), [V28.B16, V29.B16, V30.B16]

#define keys12 \
	VLD1.P	64(R8), [V18.B16, V19.B16, V20.B16, V21.B16]; \
	VLD1.P	64(R8), [V22.B16, V23.B16, V24.B16, V25.B16]; \
	VLD1.P	64(R8), [V26.B16, V27.B16, V28.B16, V29.B16]; \
	VLD1	(R8), [V30.B16]

#define keys10 \
	VLD1.P	64(R8), [V20.B16, V21.B16, V22.B16, V23.B16]; \
	VLD1.P	64(R8), [V24.B16, V25.B16, V26.B16, V27.B16]; \
	VLD1	(R8), [V28.B16, V29.B16, V30.B16]

#define dec8(K) \
	AESD	K.B16, V0.B16; AESIMC	V0.B16, V0.B16; \
	AESD	K.B16, V1.B16; AESIMC	V1.B16, V1.B16; \
	AESD	K.B16, V2.B16; AESIMC	V2.B16, V2.B16; \
	AESD	K.B16, V3.B16; AESIMC	V3.B16, V3.B16; \
	AESD	K.B16, V4.B16; AESIMC	V4.B16, V4.B16; \
	AESD	K.B16, V5.B16; AESIMC	V5.B16, V5.B16; \
	AESD	K.B16, V6.B16; AESIMC	V6.B16, V6.B16; \
	AESD	K.B16, V7.B16; AESIMC	V7.B16, V7.B16

#define dec8last(K) \
	AESD	K.B16, V0.B16; AESD	K.B16, V1.B16; \
	AESD	K.B16, V2.B16; AESD	K.B16, V3.B16; \
	AESD	K.B16, V4.B16; AESD	K.B16, V5.B16; \
	AESD	K.B16, V6.B16; AESD	K.B16, V7.B16

#define enc8(K) \
	AESE	K.B16, V0.B16; AESMC	V0.B16, V0.B16; \
	AESE	K.B16, V1.B16; AESMC	V1.B16, V1.B16; \
	AESE	K.B16, V2.B16; AESMC	V2.B16, V2.B16; \
	AESE	K.B16, V3.B16; AESMC	V3.B16, V3.B16; \
	AESE	K.B16, V4.B16; AESMC	V4.B16, V4.B16; \
	AESE	K.B16, V5.B16; AESMC	V5.B16, V5.B16; \
	AESE	K.B16, V6.B16; AESMC	V6.B16, V6.B16; \
	AESE	K.B16, V7.B16; AESMC	V7.B16, V7.B16

#define enc8last(K) \
	AESE	K.B16, V0.B16; AESE	K.B16, V1.B16; \
	AESE	K.B16, V2.B16; AESE	K.B16, V3.B16; \
	AESE	K.B16, V4.B16; AESE	K.B16, V5.B16; \
	AESE	K.B16, V6.B16; AESE	K.B16, V7.B16

#define xor8(K) \
	VEOR	V0.B16, K.B16, V0.B16; \
	VEOR	V1.B16, K.B16, V1.B16; \
	VEOR	V2.B16, K.B16, V2.B16; \
	VEOR	V3.B16, K.B16, V3.B16; \
	VEOR	V4.B16, K.B16, V4.B16; \
	VEOR	V5.B16, K.B16, V5.B16; \
	VEOR	V6.B16, K.B16, V6.B16; \
	VEOR	V7.B16, K.B16, V7.B16

#define dec1(K) AESD	K.B16, V0.B16; AESIMC	V0.B16, V0.B16
#define enc1(K) AESE	K.B16, V0.B16; AESMC	V0.B16, V0.B16

// func cbcDecAsm(p []byte, dec *byte, rounds int, iv *byte)
//
// p[i] = D(C[i]) ^ C[i-1], C[-1] = iv, in place. Each group of 8 loads its
// ciphertext twice: V0..V7 go through the rounds, V8..V15 keep C[0..7] for
// the XOR of the next blocks; V31 carries the block before the group (the
// IV, then the previous group's last ciphertext).
TEXT ·cbcDecAsm(SB), NOSPLIT, $0-48
	MOVD	p_base+0(FP), R0
	MOVD	p_len+8(FP), R1
	MOVD	dec+24(FP), R2
	MOVD	rounds+32(FP), R3
	MOVD	iv+40(FP), R4

	VLD1	(R4), [V31.B16]
	MOVD	R2, R8
	CMP	$12, R3
	BLT	dk10
	BEQ	dk12
	keys14
	B	dkdone
dk12:
	keys12
	B	dkdone
dk10:
	keys10
dkdone:
	LSR	$7, R1, R5		// groups of 8 blocks
	AND	$127, R1, R6		// bytes left after them
	CBZ	R5, dtail

dloop:
	ADD	$64, R0, R7
	VLD1	(R0), [V0.B16, V1.B16, V2.B16, V3.B16]
	VLD1	(R7), [V4.B16, V5.B16, V6.B16, V7.B16]
	VLD1	(R0), [V8.B16, V9.B16, V10.B16, V11.B16]
	VLD1	(R7), [V12.B16, V13.B16, V14.B16, V15.B16]
	CMP	$12, R3
	BLT	d8r10
	BEQ	d8r12
	dec8(V16); dec8(V17)
d8r12:
	dec8(V18); dec8(V19)
d8r10:
	dec8(V20); dec8(V21); dec8(V22); dec8(V23); dec8(V24)
	dec8(V25); dec8(V26); dec8(V27); dec8(V28)
	dec8last(V29)
	xor8(V30)
	VEOR	V0.B16, V31.B16, V0.B16
	VEOR	V1.B16, V8.B16, V1.B16
	VEOR	V2.B16, V9.B16, V2.B16
	VEOR	V3.B16, V10.B16, V3.B16
	VEOR	V4.B16, V11.B16, V4.B16
	VEOR	V5.B16, V12.B16, V5.B16
	VEOR	V6.B16, V13.B16, V6.B16
	VEOR	V7.B16, V14.B16, V7.B16
	VMOV	V15.B16, V31.B16
	VST1	[V0.B16, V1.B16, V2.B16, V3.B16], (R0)
	VST1	[V4.B16, V5.B16, V6.B16, V7.B16], (R7)
	ADD	$128, R0
	SUBS	$1, R5
	BNE	dloop

dtail:
	LSR	$4, R6, R5		// blocks left
	CBZ	R5, ddone
dtloop:
	VLD1	(R0), [V0.B16]
	VMOV	V0.B16, V8.B16
	CMP	$12, R3
	BLT	d1r10
	BEQ	d1r12
	dec1(V16); dec1(V17)
d1r12:
	dec1(V18); dec1(V19)
d1r10:
	dec1(V20); dec1(V21); dec1(V22); dec1(V23); dec1(V24)
	dec1(V25); dec1(V26); dec1(V27); dec1(V28)
	AESD	V29.B16, V0.B16
	VEOR	V0.B16, V30.B16, V0.B16
	VEOR	V0.B16, V31.B16, V0.B16
	VMOV	V8.B16, V31.B16
	VST1	[V0.B16], (R0)
	ADD	$16, R0
	SUBS	$1, R5
	BNE	dtloop
ddone:
	RET

// func ecbEncAsm(p []byte, enc *byte, rounds int)
//
// Every block of p encrypted in place, 8 at a time, then one at a time.
TEXT ·ecbEncAsm(SB), NOSPLIT, $0-40
	MOVD	p_base+0(FP), R0
	MOVD	p_len+8(FP), R1
	MOVD	enc+24(FP), R2
	MOVD	rounds+32(FP), R3

	MOVD	R2, R8
	CMP	$12, R3
	BLT	ek10
	BEQ	ek12
	keys14
	B	ekdone
ek12:
	keys12
	B	ekdone
ek10:
	keys10
ekdone:
	LSR	$7, R1, R5
	AND	$127, R1, R6
	CBZ	R5, etail

eloop:
	ADD	$64, R0, R7
	VLD1	(R0), [V0.B16, V1.B16, V2.B16, V3.B16]
	VLD1	(R7), [V4.B16, V5.B16, V6.B16, V7.B16]
	CMP	$12, R3
	BLT	e8r10
	BEQ	e8r12
	enc8(V16); enc8(V17)
e8r12:
	enc8(V18); enc8(V19)
e8r10:
	enc8(V20); enc8(V21); enc8(V22); enc8(V23); enc8(V24)
	enc8(V25); enc8(V26); enc8(V27); enc8(V28)
	enc8last(V29)
	xor8(V30)
	VST1	[V0.B16, V1.B16, V2.B16, V3.B16], (R0)
	VST1	[V4.B16, V5.B16, V6.B16, V7.B16], (R7)
	ADD	$128, R0
	SUBS	$1, R5
	BNE	eloop

etail:
	LSR	$4, R6, R5
	CBZ	R5, edone
etloop:
	VLD1	(R0), [V0.B16]
	CMP	$12, R3
	BLT	e1r10
	BEQ	e1r12
	enc1(V16); enc1(V17)
e1r12:
	enc1(V18); enc1(V19)
e1r10:
	enc1(V20); enc1(V21); enc1(V22); enc1(V23); enc1(V24)
	enc1(V25); enc1(V26); enc1(V27); enc1(V28)
	AESE	V29.B16, V0.B16
	VEOR	V0.B16, V30.B16, V0.B16
	VST1	[V0.B16], (R0)
	ADD	$16, R0
	SUBS	$1, R5
	BNE	etloop
edone:
	RET
