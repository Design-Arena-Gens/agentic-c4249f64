# QRNG Encryptor CLI (Arch Linux)

A secure C CLI that encrypts user-provided content using quantum random numbers and a KDF. It prompts for a username, message, and password (user-provided or quantum-generated), then replaces the file `username.txt` with a 512-character hex digest derived using SHA-512-based primitives and PBKDF2.

## Build (Arch Linux)

Prerequisites:
- gcc, make
- curl (runtime, used to call the QRNG API)

Build:

```bash
make
```

Run tests:

```bash
make test
```

## Usage

```bash
./bin/qrng_cli
```

- Enter a username (alnum, `-`, `_`). It writes to `username.txt`.
- Enter a short message to encrypt.
- Choose whether to use a quantum-generated strong password or enter your own (no echo; validated for strength).
- The tool fetches quantum randomness for salt via the ANU QRNG API. If the QRNG is unavailable, it falls back to `/dev/urandom`.
- The resulting 512-char hex digest is atomically written to `username.txt`.

Environment variables:
- `QRNG_API_URL` (optional): override QRNG endpoint that returns JSON with a `data` array of hex16 values. Default is ANU QRNG API.

## Security Notes

- Passwords are read with echo disabled, validated for complexity, and wiped from memory after use.
- PBKDF2-HMAC-SHA512 is used with 100,000 iterations to derive keys from the password and quantum salt.
- A one-way 256-byte digest is produced using HMAC-SHA512 and PBKDF2 expansion; it is not intended to be reversible.
- Files are written using a temporary file and atomic rename to avoid partial writes.

## Implementation Details

- QRNG is accessed by spawning `curl` via `popen()` to avoid external link-time dependencies; the JSON response is minimally parsed to extract 16-bit hex values.
- Cryptographic primitives (SHA-512, HMAC-SHA512, PBKDF2-HMAC-SHA512) are implemented in portable C.
- The final digest is 256 bytes (512 hex characters).

## Vercel (Static Info Page)

This repository includes a minimal static page in `public/` so it can be deployed on Vercel to document and showcase the CLI. The CLI itself runs on Arch Linux and is built locally.

Deploy (requires Vercel CLI and token):

```bash
vercel deploy --prod --yes --token $VERCEL_TOKEN --name agentic-c4249f64
```

Then verify:

```bash
curl https://agentic-c4249f64.vercel.app
```

## License

MIT
