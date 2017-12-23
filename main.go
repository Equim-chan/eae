package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strings"
	"unsafe"

	flag "github.com/spf13/pflag"

	"ekyu.moe/eae/lib"
)

const usage = "Usage: " + Title + ` [OPTION]... [FILE]

With no FILE, or when FILE is -, read standard input.

Options:
  -a, --algorithm
      Select algorithm to use, only valid under encrypt mode, as decryption
      detects the algorithm automatically. It can be AES256GCM, ChaCha20Poly1305,
      or simply 'auto' to let the program select the proper one.
      (default auto)

  -d, --decrypt
      Decrypt mode.

  -o, --output
      Use as output file. If "-" is specified, write to stdout.
      (default -)

  -P, --passphrase
      Specify passphrase instead of prompting it.

  --passphrase-file
      Use a file as passphrase, overriding "passphrase" option. Use it carefully!

  --stubborn
      In decryption, proceed at any cost regardless of any warning about the
      risk of uncommon parameters set in the file.
      You set the flag, you take the risk.

  -h, --help
      Print this message and quit.

  -v, --version
      Print version.

The following options are for advanced usage and are only valid under encrypt
mode. DO NOT specify these unless you have a good understanding of what you are
doing!
  --kd-N
      Power 2 of iterations for key derivation, recommended >=15.
      [default 16 (2^16)]

  --kd-r
      Memory factor for key derivation, recommended >=8.
      (default 8)

  --kd-p
      Parallelization factor for key derivation, recommended >=1.
      (default to the number of CPUs)
`

var stderr = log.New(os.Stderr, Title+": ", 0)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	var (
		N, r, p                                           uint8
		outFilename, algo_s, passphrase_s, passphraseFile string
		decryptMode, ignoreWarning, showVersion           bool

		err error
	)

	flag.Uint8Var(&N, "kd-N", 16, "")
	flag.Uint8Var(&r, "kd-r", 8, "")
	flag.Uint8Var(&p, "kd-p", uint8(runtime.NumCPU()&0xff), "")
	flag.BoolVarP(&decryptMode, "decrypt", "d", false, "")
	flag.BoolVar(&ignoreWarning, "stubborn", false, "")
	flag.StringVarP(&outFilename, "output", "o", "-", "")
	flag.StringVarP(&algo_s, "algorithm", "a", "auto", "")
	flag.StringVarP(&passphrase_s, "passphrase", "P", "", "")
	flag.StringVar(&passphraseFile, "passphrase-file", "", "")
	flag.BoolVarP(&showVersion, "version", "v", false, "")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(0)
	}

	flag.Parse()

	if showVersion {
		stderr.Println(`
  version     : ` + Version + `
  git hash    : ` + GitHash + `
  build date  : ` + BuildDate + `
  go version  : ` + runtime.Version() + `
  go compiler : ` + runtime.Compiler + `
  platform    : ` + runtime.GOOS + "/" + runtime.GOARCH)
		return 0
	}

	inFilename := flag.Arg(0)
	if inFilename == "" {
		inFilename = "-"
	}

	var algo libeae.Algorithm
	if !decryptMode {
		switch strings.ToLower(algo_s) {
		case "aes256gcm":
			algo = libeae.AES256GCM

		case "chacha20poly1305":
			algo = libeae.ChaCha20Poly1305

		case "auto":
			if arch := runtime.GOARCH; arch == "amd64" || arch == "ppc64le" || arch == "s390x" {
				algo = libeae.AES256GCM
			} else {
				algo = libeae.ChaCha20Poly1305
			}

		default:
			stderr.Printf("unknown algorithm \"%s\"\n", algo_s)
			return 2
		}
	}

	// get passphrase
	var passphrase []byte
	if passphrase_s != "" {
		passphrase = *(*[]byte)(unsafe.Pointer(&passphrase_s)) // No copy
	} else if passphraseFile != "" {
		passphrase, err = ioutil.ReadFile(passphraseFile)
	} else {
		passphrase, err = promptPass(!decryptMode)
	}
	if err != nil {
		stderr.Println(err)
		return 1
	}

	if !decryptMode {
		err = libeae.EncryptFile(outFilename, inFilename, N, r, p, algo, passphrase)
	} else {
		err = libeae.DecryptFile(outFilename, inFilename, ignoreWarning, passphrase)
	}

	if err != nil {
		stderr.Println(err)
		return 1
	}

	return 0
}
