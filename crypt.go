package kcp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/tea"
)

var (
	initialVector = []byte{167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107}
	saltxor       = `sH3CIVoF#rWLtJo6`
)

type BlockCrypt interface {
	// Encrypt encrypts the whole block in src into dst.
	// Dst and src may point at the same memory.
	Encrypt(dst, src []byte)

	// Decrypt decrypts the whole block in src into dst.
	// Dst and src may point at the same memory.
	Decrypt(dst, src []byte)
}

// AES Block Encryption
type AESBlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

func NewAESBlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(AESBlockCrypt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, aes.BlockSize)
	c.decbuf = make([]byte, 2*aes.BlockSize)
	return c, nil
}

func (c *AESBlockCrypt) Encrypt(dst, src []byte) {
	encrypt(c.block, dst, src, c.encbuf)
}

func (c *AESBlockCrypt) Decrypt(dst, src []byte) {
	decrypt(c.block, dst, src, c.decbuf)
}

// TEA Block Encryption
type TEABlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

func NewTEABlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(TEABlockCrypt)
	block, err := tea.NewCipherWithRounds(key, 16)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, tea.BlockSize)
	c.decbuf = make([]byte, 2*tea.BlockSize)
	return c, nil
}

func (c *TEABlockCrypt) Encrypt(dst, src []byte) {
	encrypt(c.block, dst, src, c.encbuf)
}

func (c *TEABlockCrypt) Decrypt(dst, src []byte) {
	decrypt(c.block, dst, src, c.decbuf)
}

// Simple XOR Block Encryption, insecure
type SimpleXORBlockCrypt struct {
	xortbl []byte
}

func NewSimpleXORBlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(SimpleXORBlockCrypt)
	c.xortbl = pbkdf2.Key(key, []byte(saltxor), 1024, mtuLimit, sha1.New)
	return c, nil
}

func (c *SimpleXORBlockCrypt) Encrypt(dst, src []byte) {
	xorBytes(dst, src, c.xortbl)
}

func (c *SimpleXORBlockCrypt) Decrypt(dst, src []byte) {
	xorBytes(dst, src, c.xortbl)
}

// packet encryption with local CFB mode
func encrypt(block cipher.Block, dst, src, buf []byte) {
	blocksize := block.BlockSize()
	tbl := buf[:blocksize]
	block.Encrypt(tbl, initialVector)
	n := len(src) / blocksize
	base := 0
	for i := 0; i < n; i++ {
		xorWords(dst[base:], src[base:], tbl)
		block.Encrypt(tbl, dst[base:])
		base += blocksize
	}
	xorBytes(dst[base:], src[base:], tbl)
}

func decrypt(block cipher.Block, dst, src, buf []byte) {
	blocksize := block.BlockSize()
	tbl := buf[:blocksize]
	next := buf[blocksize:]
	block.Encrypt(tbl, initialVector)
	n := len(src) / blocksize
	base := 0
	for i := 0; i < n; i++ {
		block.Encrypt(next, src[base:])
		xorWords(dst[base:], src[base:], tbl)
		tbl, next = next, tbl
		base += blocksize
	}
	xorBytes(dst[base:], src[base:], tbl)
}
