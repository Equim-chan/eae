// Package aeadstream implements streams on AEAD ciphers.
package aeadstream

import (
	"crypto/cipher"
	"errors"
	"io"

	"ekyu.moe/util/bytesutil"
)

// AEADStream is a wrapper of cipher.AEAD.
type AEADStream struct {
	cipher.AEAD
	nonceSize int
	overhead  int
}

// NewAEADStream creates an AEADStream based on c.
func NewAEADStream(c cipher.AEAD) *AEADStream {
	return &AEADStream{c, c.NonceSize(), c.Overhead()}
}

// incCounter applies plus-one to a in little endian.
func incCounter(a []byte) error {
	for i := 0; i < len(a); i++ {
		a[i]++
		if a[i] != 0x0 {
			return nil
		}
	}

	return errors.New("aeadstream: counter overflow")
}

// StreamEncrypt encrypts data from r and writes cipher text to w.
// cipher.AEAD.Seal is processed every chunkSize of data read.
// nonceSeed is the seed of nonce, must either be nil or the same size as
// NonceSize() of the AEAD cipher.
//
// The number of bytes written to w is returned. If and only if the returned
// error is nil, either reading from r or writing to w met EOF.
func (as *AEADStream) StreamEncrypt(w io.Writer, r io.Reader, nonceSeed []byte, chunkSize int) (int64, error) {
	seed := nonceSeed
	if seed == nil {
		seed = make([]byte, as.nonceSize)
	}
	if len(seed) != as.nonceSize {
		return 0, errors.New("aeadstream: wrong size of nonce seed")
	}

	nonce := make([]byte, as.nonceSize)
	counter := make([]byte, as.nonceSize)
	copy(nonce, seed)

	// chunk consists of block and aead tag data
	chunk := make([]byte, chunkSize+as.overhead)

	var written int64
	var n int
	var err error

	for {
		n, err = io.ReadFull(r, chunk[:chunkSize])
		switch {
		case err == io.ErrUnexpectedEOF:
			// when the remaining input cannot suffuse the chunk
			chunk = chunk[:n+as.overhead]

		case err == io.EOF:
			// when the last read input exactly suffuse the chunk
			// normally, with no actual error, the loop should break here
			return written, nil

		case err != nil:
			return written, err
		}

		bytesutil.XorBytes(nonce, nonce, counter)
		if err = incCounter(counter); err != nil {
			return written, err
		}

		as.Seal(chunk[:0], nonce, chunk[:n], nil)

		n, err = w.Write(chunk)
		written += int64(n)
		if err != nil {
			return written, err
		}
	}
}

// StreamDecrypt decrypts data from r and writes plain text to w.
// cipher.AEAD.Open is processed every chunkSize of data read.
// nonceSeed is the seed of nonce, must either be nil or the same size as
// NonceSize() of the AEAD cipher.
//
// The number of bytes written to w is returned. If and only if the returned
// error is nil, either reading from r or writing to w met EOF. It is guaranteed
// that unauthorized data is never written to w.
func (as *AEADStream) StreamDecrypt(w io.Writer, r io.Reader, nonceSeed []byte, chunkSize int) (int64, error) {
	seed := nonceSeed
	if seed == nil {
		seed = make([]byte, as.nonceSize)
	}
	if len(seed) != as.nonceSize {
		return 0, errors.New("aeadstream: wrong size of nonce seed")
	}

	nonce := make([]byte, as.nonceSize)
	counter := make([]byte, as.nonceSize)
	copy(nonce, seed)

	chunk := make([]byte, chunkSize+as.overhead)

	var written int64
	var n int
	var err error

	for {
		n, err = io.ReadFull(r, chunk)
		switch {
		case err == io.ErrUnexpectedEOF:
			// when the remaining input cannot suffuse the chunk
			chunk = chunk[:n]

		case err == io.EOF:
			// when the last read input exactly suffuse the chunk
			// normally, with no actual error, the loop should break here
			return written, nil

		case err != nil:
			return written, err
		}

		bytesutil.XorBytes(nonce, nonce, counter)
		if err = incCounter(counter); err != nil {
			return written, err
		}

		if _, err = as.Open(chunk[:0], nonce, chunk, nil); err != nil {
			// when it comes to here, err is very likely to be an auth failed error
			return written, err
		}

		n, err = w.Write(chunk[:n-as.overhead])
		written += int64(n)
		if err != nil {
			return written, err
		}
	}
}
