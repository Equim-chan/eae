package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"

	"ekyu.moe/util/cli"
	"golang.org/x/crypto/ssh/terminal"
)

func promptPass(needComfirm bool) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !terminal.IsTerminal(fd) {
		r, err := cli.NewTTYReader()
		if err != nil {
			return nil, fmt.Errorf("read passphrase: failed to create tty reader: %s", err)
		}
		defer r.Close()

		if fd = int(r.Fd()); !terminal.IsTerminal(fd) {
			return nil, errors.New("read passphrase: no tty available, while neither `--passphrase' nor `--passphrase-file' was specified")
		}
	}

	for {
		fmt.Fprint(os.Stderr, "Enter passphrase: ")
		input0, err := terminal.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("read passphrase: %s", err)
		}

		if len(input0) == 0 {
			fmt.Fprintln(os.Stderr, "Passphrases cannot be empty. Try again.")
			continue
		}

		if needComfirm {
			fmt.Fprint(os.Stderr, "Enter same passphrase again: ")
			input1, err := terminal.ReadPassword(fd)
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return nil, fmt.Errorf("read passphrase: %s", err)
			}

			if subtle.ConstantTimeCompare(input0, input1) == 0 {
				fmt.Fprintln(os.Stderr, "Passphrases do not match. Try again.")
				continue
			}
		}

		return []byte(input0), nil
	}
}
