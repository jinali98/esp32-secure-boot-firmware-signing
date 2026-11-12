# ESP32 secure boot and firmware signing

A classic ESP32 that only boots firmware it can trust.

The goal of this project is to build a secure firmware setup for the ESP32, covering:

- **Secure Boot:** The chip only runs firmware signed with our private key (Secure Boot V2).
- **Flash Encryption:** Firmware and keys are stored encrypted, so even if someone dumps the flash over USB, they get ciphertext rather than readable secrets.
- **Device Identity:** Each device has its own certificate and authenticates itself to a Go server using mutual TLS (mTLS).
- **Signed OTA Updates:** The device only installs signed firmware updates and automatically rolls back if a new version fails to start.

## Current Status

This is still a work in progress. So far, the focus has been on the signing side. There are Go tools to sign firmware images and verify their signatures, performing the same kind of check the ESP32 does when it boots.

| CLI           | Algorithm                           | Why                                                                                                                                      |
| ------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `cmd/ed25519` | Ed25519                             | Small, deterministic signatures, kept for comparison                                                                                     |
| `cmd/rsa`     | RSA-3072 PSS, SHA-256, 32-byte salt | The scheme classic ESP32 [Secure Boot V2](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/security/secure-boot-v2.html) uses |

## Requirements

- Go 1.26.3 or newer (see `go.mod`). Install from [go.dev/dl](https://go.dev/dl/).

## Setup

```bash
git clone https://github.com/jinali98/esp32-secure-boot-firmware-signing.git
cd esp32-secure-boot-firmware-signing
go build ./...
```

`go build ./...` compiles both CLIs to check they build. It doesn't write binaries when it
builds more than one package.

## Usage

Both CLIs take the same three commands. They read and write files relative to the
**current directory**, so run each CLI from inside its own folder. Its keys then land in
that folder's `keys/`.

```bash
cd cmd/rsa
echo "pretend firmware" > firmware.bin

go run . keygen              # creates keys/ (0700), writes keys/private.pem (0600) and keys/public.pem
go run . sign firmware.bin   # writes firmware.sig
go run . verify firmware.bin # prints VALID or INVALID
```

For Ed25519, do the same in `cmd/ed25519`. Its keys are `keys/private.key` and
`keys/public.key` (raw bytes, 64 and 32 long).

| Exit code | Meaning                                               |
| --------- | ----------------------------------------------------- |
| 0         | Success, or `VALID`                                   |
| 1         | `INVALID`, bad usage, or an error (message on stderr) |

`go run` reports exit status 1 on any failure. To see the program's own code, build it first:
`go build -o rsa-cli .` (inside `cmd/rsa`).

## Break-it tests

1. Change one character in `firmware.bin`, then run `verify`. Expect `INVALID`, as the
   signature covers every byte, so modified firmware is rejected.
2. Run `keygen` again, then `verify` the old signature. Expect `INVALID` as a signature only
   checks out against the public key of the private key that made it.

## Key safety

- `keys/` folders, `*.pem`, `*.key`, `*.sig` and `firmware.bin` are in `.gitignore`. Never
  commit them.
- These are throwaway keys stored as plain files. A real firmware signing key stays
  offline or in an HSM.

## Hardware (next stage)

Board: NodeMCU ESP32 dev board (classic ESP32). To talk to it over USB, install
[esptool](https://docs.espressif.com/projects/esptool/en/latest/esp32/):

```bash
brew install esptool
```

To find the board's serial port, run `ls /dev/cu.*` once with the board unplugged and once
plugged in. The new entry is the board
([Espressif guide](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/establish-serial-connection.html)).
`esptool chip-id` then prints the chip revision. Secure Boot V2 needs revision 3.0 or newer.

## Layout

```
cmd/ed25519/main.go     Ed25519 keygen / sign / verify
cmd/ed25519/keys/       Ed25519 keys (created by keygen, git-ignored)
cmd/rsa/main.go         RSA-3072 PSS keygen / sign / verify
cmd/rsa/keys/           RSA keys (created by keygen, git-ignored)
docs/system_design.png  Device, boot, update and mTLS design
```
