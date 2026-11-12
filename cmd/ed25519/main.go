package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

const (
	keyDir        = "keys"
	signatureFile = "firmware.sig"
)

var (
	privateKeyFile = filepath.Join(keyDir, "private.key")
	publicKeyFile  = filepath.Join(keyDir, "public.key")
)

func main() {
	flag.Parse()

	cmdValue := flag.Args()

	if len(cmdValue) < 1 {
		usage()
	}

	switch cmdValue[0] {
	case "keygen":
		if err := keygen(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("wrote", privateKeyFile, "and", publicKeyFile)
	case "sign":
		if len(cmdValue) < 2 {
			usage()
		}
		if err := sign(cmdValue[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("wrote", signatureFile)
	case "verify":
		if len(cmdValue) < 2 {
			usage()
		}
		isValid, err := verify(cmdValue[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if !isValid {
			fmt.Println("INVALID")
			os.Exit(1)
		}
		fmt.Println("VALID")
	default:
		usage()
	}
}

// usage prints how to call the program and exits with status 1.
func usage() {
	fmt.Fprintln(os.Stderr, "usage: cli <keygen|sign|verify> [file]")
	os.Exit(1)
}

func keygen() error {
	// 0700: only the owner can list or enter the folder holding the private key.
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf("creating %s: %w", keyDir, err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	err = os.WriteFile(privateKeyFile, privateKey, 0600)
	if err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}

	err = os.WriteFile(publicKeyFile, publicKey, 0644)
	if err != nil {
		return fmt.Errorf("writing public key: %w", err)
	}

	return nil
}

func sign(codePath string) error {
	privateKey, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return fmt.Errorf("reading private key: %w", err)
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(privateKey))
	}

	content, err := os.ReadFile(codePath)
	if err != nil {
		return fmt.Errorf("reading firmware: %w", err)
	}

	sig := ed25519.Sign(privateKey, content)

	err = os.WriteFile(signatureFile, sig, 0644)
	if err != nil {
		return fmt.Errorf("writing signature: %w", err)
	}

	return nil
}

func verify(codePath string) (bool, error) {
	publicKey, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return false, fmt.Errorf("reading public key: %w", err)
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(publicKey))
	}

	content, err := os.ReadFile(codePath)
	if err != nil {
		return false, fmt.Errorf("reading firmware: %w", err)
	}

	sig, err := os.ReadFile(signatureFile)
	if err != nil {
		return false, fmt.Errorf("reading signature: %w", err)
	}

	if len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("corrupt signature file: must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}

	return ed25519.Verify(publicKey, content, sig), nil
}
