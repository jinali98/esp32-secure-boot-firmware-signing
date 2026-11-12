package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
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
	privateKeyFile = filepath.Join(keyDir, "private.pem")
	publicKeyFile  = filepath.Join(keyDir, "public.pem")
)

// pssOptions matches ESP32 Secure Boot V2: SHA-256 and a 32-byte salt.
// sign and verify share it so the two sides can't drift apart.
var pssOptions = &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}

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

// the private key as PKCS #8, the public key as PKIX.
func keygen() error {
	// 0700: only the owner can list or enter the folder holding the private key.
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf("creating %s: %w", keyDir, err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshalling private key: %w", err)
	}

	encodedPrivateKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})

	err = os.WriteFile(privateKeyFile, encodedPrivateKey, 0600)
	if err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}

	der, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("marshalling public key: %w", err)
	}

	encodedPublicKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})

	err = os.WriteFile(publicKeyFile, encodedPublicKey, 0644)
	if err != nil {
		return fmt.Errorf("writing public key: %w", err)
	}

	return nil
}

// sign hashes the file at codePath with SHA-256, signs the digest with
// RSA-PSS and writes the signature to signatureFile.
func sign(codePath string) error {
	// read the private key file
	encodedPrivateKey, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return fmt.Errorf("reading private key: %w", err)
	}

	// read the code file
	content, err := os.ReadFile(codePath)
	if err != nil {
		return fmt.Errorf("reading firmware: %w", err)
	}

	block, _ := pem.Decode(encodedPrivateKey)
	if block == nil {
		return fmt.Errorf("no PEM data in %s", privateKeyFile)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing private key: %w", err)
	}

	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is %T, not RSA", key)
	}

	hashedContent := sha256.Sum256(content)

	sig, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashedContent[:], pssOptions)
	if err != nil {
		return fmt.Errorf("signing firmware: %w", err)
	}

	err = os.WriteFile(signatureFile, sig, 0644)
	if err != nil {
		return fmt.Errorf("writing signature: %w", err)
	}

	return nil
}

func verify(codePath string) (bool, error) {
	// read the public key file
	encodedPublicKey, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return false, fmt.Errorf("reading public key: %w", err)
	}

	// read the code file
	content, err := os.ReadFile(codePath)
	if err != nil {
		return false, fmt.Errorf("reading firmware: %w", err)
	}

	sig, err := os.ReadFile(signatureFile)
	if err != nil {
		return false, fmt.Errorf("reading signature: %w", err)
	}

	block, _ := pem.Decode(encodedPublicKey)
	if block == nil {
		return false, fmt.Errorf("no PEM data in %s", publicKeyFile)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parsing public key: %w", err)
	}

	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("public key is %T, not RSA", key)
	}

	if len(sig) != publicKey.Size() {
		return false, fmt.Errorf("corrupt signature file: must be %d bytes, got %d", publicKey.Size(), len(sig))
	}

	hashedContent := sha256.Sum256(content)

	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, hashedContent[:], sig, pssOptions); err != nil {
		return false, nil
	}

	return true, nil
}
