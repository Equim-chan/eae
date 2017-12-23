package libeae

const (
	KeySize   = 32
	SaltSize  = 16
	NonceSize = 12
	ChunkSize = 256 * 1024

	AES256GCM        = 'A'
	ChaCha20Poly1305 = 'C'
)

var (
	magic = [7]byte{'E', 'a', 'E', 0xea, 0xe0, 0x17, 0xef}
)

type Algorithm uint8
