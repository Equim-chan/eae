package libeae

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"

	"ekyu.moe/eae/lib/aeadstream"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

func DecryptFile(outFilename, inFilename string, ignoreWarning bool, passphrase []byte) error {
	var inFile, outFile *os.File
	var err error

	// open in file
	if inFilename == "-" {
		inFile = os.Stdin
	} else {
		inFile, err = os.OpenFile(inFilename, os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer inFile.Close()
	}

	// create out file
	if outFilename == "-" {
		outFile = os.Stdout
	} else {
		outFile, err = os.OpenFile(outFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer outFile.Close()
	}

	// read header
	header := make([]byte, 7+SaltSize+NonceSize+4)
	if _, err := inFile.Read(header); err != nil {
		return fmt.Errorf("read header: %s", err)
	}

	// parse and validate header
	fileMagic := header[:7]
	if bytes.Compare(fileMagic, magic[:]) != 0 {
		return fmt.Errorf("parse header: not a valid eae encrypted file")
	}

	salt := header[7 : 7+SaltSize]
	nonceSeed := header[7+SaltSize : 7+SaltSize+NonceSize]
	N := header[7+SaltSize+NonceSize]
	r := header[7+SaltSize+NonceSize+1]
	p := header[7+SaltSize+NonceSize+2]
	algo := header[7+SaltSize+NonceSize+3]
	if N == 0 || r == 0 || p == 0 || algo != AES256GCM && algo != ChaCha20Poly1305 {
		return fmt.Errorf("parse header: not a valid eae encrypted file")
	}
	if N > 20 || r > 12 || p > 8 {
		fmt.Fprintln(os.Stderr, `[WARN] The file has been encrypted with an uncommon set of params!
Or it is not encrypted by this application at all. This file is
likely compromised and not what you want to decrypt. Proceed
decrypting is risky and will take longer time and larger memory.`)
		if !ignoreWarning {
			fmt.Fprintln(os.Stderr, "Re-run eae with --stubborn if you insist on decrypting it")
			return fmt.Errorf("parse header: uncommon parameters")
		}
	}

	// key derivation with scrypt
	key, err := scrypt.Key(passphrase, salt, 1<<N, int(r), int(p), 32)
	if err != nil {
		return fmt.Errorf("key derivation: %s", err)
	}

	// create aead cipher
	var aead cipher.AEAD
	switch algo {
	case AES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return fmt.Errorf("create aead: %s", err)
		}

		aead, err = cipher.NewGCMWithNonceSize(block, NonceSize)
		if err != nil {
			return fmt.Errorf("create aead: %s", err)
		}

	case ChaCha20Poly1305:
		aead, err = chacha20poly1305.New(key)
		if err != nil {
			return fmt.Errorf("create aead: %s", err)
		}

	default:
		panic("shouldn't reach")
	}

	// on to the core business
	s := aeadstream.NewAEADStream(aead)
	if _, err := s.StreamDecrypt(outFile, inFile, nonceSeed, ChunkSize); err != nil {
		return fmt.Errorf("decrypt: %s (likely wrong passphrase!)", err)
	}

	return nil
}
