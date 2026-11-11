package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
)

func main() {
	flag.Parse()

	cmdValue := flag.Args()

	if len(cmdValue) < 1 {
		usage()
	}

	switch cmdValue[0] {
	case "keygen":
		keygen()
		fmt.Println("wrote privkey.txt and pubkey.txt")
	case "verify":
		if len(cmdValue) < 2 {
			usage()
		}
		if verify(cmdValue[1]) {
			fmt.Println("VALID")
		} else {
			fmt.Println("INVALID")
			os.Exit(1)
		}
	case "sign":
		if len(cmdValue) < 2 {
			usage()
		}
		sign(cmdValue[1])
		fmt.Println("wrote firmware.sig")
	default:
		usage()
	}
}

// usage prints how to call the program and exits with status 1.
func usage() {
	fmt.Fprintln(os.Stderr, "usage: cli <keygen|sign|verify> [file]")
	os.Exit(1)
}

func keygen() {

	// generate the key pair
	pubKey, privkey, err := ed25519.GenerateKey(nil)

	// handle any error
	if err != nil {
		fmt.Fprintf(os.Stderr, "generating key failed: %v\n", err)
		os.Exit(1)
	}
	// write the keys to a folder /keys/prv_date.key keys/pub_date.key
	k1 := []byte(privkey)
	k2 := []byte(pubKey)

	err = os.WriteFile("pubkey.txt", k2, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "writing public key: %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile("privkey.txt", k1, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "writing private key: %v\n", err)
		os.Exit(1)
	}

}

func sign(codePath string) {

	// read the key file
	privateKey, err := os.ReadFile("privkey.txt")

	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading private key: %v\n", err)
		os.Exit(1)
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "private key must be %d bytes, got %d\n", ed25519.PrivateKeySize, len(privateKey))
		os.Exit(1)
	}

	// read the code file
	content, err := os.ReadFile(codePath)

	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading firmware: %v\n", err)

		os.Exit(1)
	}

	// sign the msg
	signature := ed25519.Sign(privateKey, content)

	err = os.WriteFile("firmware.sig", signature, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "writing signature failed: %v\n", err)
		os.Exit(1)
	}

}

func verify(codePath string) bool {

	// read the public file
	publicKey, err := os.ReadFile("pubkey.txt")

	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading public key: %v\n", err)
		os.Exit(1)
	}

	if len(publicKey) != ed25519.PublicKeySize {
		fmt.Fprintf(os.Stderr, "public key must be %d bytes, got %d\n", ed25519.PublicKeySize, len(publicKey))
		os.Exit(1)
	}

	// read the code file
	content, err := os.ReadFile(codePath)

	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading firmware: %v\n", err)
		os.Exit(1)
	}

	// read the signature file
	sig, err := os.ReadFile("firmware.sig")

	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading firmware signature: %v\n", err)
		os.Exit(1)
	}

	if len(sig) != ed25519.SignatureSize {
		fmt.Fprintf(os.Stderr, "corrupt signature file: must be %d bytes, got %d\n", ed25519.SignatureSize, len(sig))
		os.Exit(1)
	}

	isValid := ed25519.Verify(publicKey, content, sig)

	return isValid
}
