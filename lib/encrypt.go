package libeae

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"

	"ekyu.moe/eae/lib/aeadstream"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

func EncryptFile(outFilename, inFilename string, N, r, p uint8, algo Algorithm, passphrase []byte) error {
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

	// generate salt
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("gen salt: %s", err)
	}

	// key derivation with scrypt
	key, err := scrypt.Key(passphrase, salt, 1<<N, int(r), int(p), KeySize)
	if err != nil {
		return fmt.Errorf("key derivation: %s", err)
	}

	// generate nonceSeed
	nonceSeed := make([]byte, NonceSize)
	if _, err := rand.Read(nonceSeed); err != nil {
		return fmt.Errorf("generate nonceSeed: %s", err)
	}

	// write header
	header := make([]byte, 0, 7+SaltSize+NonceSize+4)
	header = append(header, magic[:]...)
	header = append(header, salt...)
	header = append(header, nonceSeed...)
	header = append(header, N, r, p, uint8(algo))
	if _, err := outFile.Write(header); err != nil {
		return fmt.Errorf("write header: %s", err)
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
	if _, err := s.StreamEncrypt(outFile, inFile, nonceSeed, ChunkSize); err != nil {
		return fmt.Errorf("encrypt: %s", err)
	}

	return nil
}
