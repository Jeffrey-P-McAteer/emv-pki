# emv-pki

Use an EMV chip card (Visa, Mastercard, Amex, etc.) as a hardware security token
to sign messages and verify signatures.  The card's private key never leaves the
chip — it is used only through the card's own INTERNAL AUTHENTICATE command.

**All operations that touch the card require a real card in a reader.**
Verification of an existing signature requires no card, no reader, and no
OS-specific setup — send the `signature.json` file to anyone on any platform.

---

## Requirements

### Hardware

A PC/SC-compliant **contact** smart card reader.  Any CCID-compliant USB reader
works on all platforms without a vendor driver:

- ACS ACR38U, ACR39U, ACR1252U
- HID Global OMNIKEY 3121
- Identive / SCM SCR3310, SCR3500
- Gemalto PC Twin Reader (install vendor driver for best results)

The reader must be a **contact** type — standard payment cards have a gold chip
on the front and are inserted face-up into the reader slot.

### Python

Python 3.12+ and [uv](https://astral.sh/uv).  Dependencies (`pyscard`,
`cryptography`) are declared inline and installed automatically by `uv` on first
run.

---

## Setup

### Linux

Install `uv`, start the PC/SC daemon, then run:

```sh
pip install uv                        # or: curl -LsSf https://astral.sh/uv/install.sh | sh
sudo systemctl enable --now pcscd
./emv-pki.py <command> [options]
```

If you see a polkit / "Access denied" error the script will automatically
re-run itself with `sudo`.

### Windows

Windows includes a built-in smart card service (`SCardSvr`) that starts
automatically when a reader is plugged in — no daemon or driver installation
is needed for CCID-compliant readers.

Install `uv` once:

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Then run every command with `uv run`:

```cmd
uv run emv-pki.py <command> [options]
```

> **Note:** Windows does not execute the shebang line at the top of the script,
> so `./emv-pki.py` will not work.  Always use `uv run emv-pki.py`.

Standard interactive users can access the smart card reader without elevated
privileges.  If you get an `SCARD_E_NO_SERVICE` error, plug in the reader and
try again — the service starts on demand when a reader is detected.

---

## Card compatibility

The sign command requires Dynamic Data Authentication (DDA), which gives the
card a unique RSA private key per-chip.  Run `info` to check whether your card
supports it:

**Linux:**
```sh
./emv-pki.py info
```

**Windows:**
```cmd
uv run emv-pki.py info
```

```
━━━ EMV Card Info ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Network:     Visa
  AID:         A0000000031010
  Cardholder:  LAST/FIRST I
  PAN:         ****1234
  Expiry:      12/28

  ─── Authentication Capabilities ───
  AIP:          E000
  SDA support:  No
  DDA support:  Yes       ← required for signing
  CDA support:  Yes
```

Cards that show only `SDA support: Yes` have no per-chip private key and cannot
sign.

---

## Signing a message

Insert the card, then run:

**Linux:**
```sh
./emv-pki.py sign --message "I approve this transaction" --output approval.json
```

**Windows:**
```cmd
uv run emv-pki.py sign --message "I approve this transaction" --output approval.json
```

```
━━━ Sign Data with Card ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Reading card and initiating DDA flow...
  Cardholder:  LAST/FIRST I
  Message:     'I approve this transaction'
  Commitment:  SHA256(message + cardholder) → A3F21C08 (UN)
  DDOL: not present (using default: 4-byte Unpredictable Number)
  Requesting SDAD (INTERNAL AUTHENTICATE)...

  Auth data: A3F21C08  (4 bytes)
  SDAD:      0A3D4AF2F717A01B...  (144 bytes)

  SDAD structure verified against ICC public key
  Format: 0x05 (expected 0x05 for DDA SDAD)
  ICC Dynamic Number: 3B9A12F0
  Hash check: OK

  Saved to: approval.json
  ICC public key embedded — verify requires no card or separate PEM.
```

The output file is a self-contained JSON bundle:

```json
{
  "version": "1",
  "algorithm": "EMV-DDA-INTERNAL-AUTHENTICATE",
  "network": "Visa",
  "cardholder": "LAST/FIRST I",
  "message": "I approve this transaction",
  "auth_data": "a3f21c08",
  "sdad": "Cj1...",
  "sdad_len": 144,
  "timestamp": "2026-02-18T16:00:00.000000Z",
  "icc_public_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
}
```

### How the signing works

1. The tool computes a **commitment**:
   `SHA-256(message + NUL + cardholder)`, and takes the first 4 bytes as the
   Unpredictable Number (terminal dynamic data).
2. The card's chip receives this value via the EMV INTERNAL AUTHENTICATE command
   and produces a **Signed Dynamic Application Data (SDAD)** — an RSA signature
   using the card's private key, covering its own dynamic data and the
   Unpredictable Number.
3. Because the Unpredictable Number is derived deterministically from the
   message **and** the cardholder name, the SDAD cryptographically binds the
   specific card, the specific cardholder identity, and the specific message
   together.

The card's ICC public key (recovered from the full EMV certificate chain
CA → Issuer → ICC) is embedded in the JSON so the verifier needs nothing else.

---

## Verifying a signature

No card, no reader, and no platform-specific setup is needed.  The ICC public
key is embedded in the signature bundle.  Send `approval.json` to the recipient
by any means (email, messaging, shared drive) and they verify it with:

**Linux:**
```sh
./emv-pki.py verify --signature approval.json
```

**Windows:**
```cmd
uv run emv-pki.py verify --signature approval.json
```

```
━━━ Verify Signature ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Algorithm:   EMV-DDA-INTERNAL-AUTHENTICATE
  Network:     Visa
  Cardholder:  LAST/FIRST I
  Message:     'I approve this transaction'
  Timestamp:   2026-02-18T16:00:00.000000Z
  Auth data:   A3F21C08  (4 bytes)
  SDAD:        0A3D4AF2F717A01B...  (144 bytes)

  Commitment check: SHA256(message + cardholder)[:4] = A3F21C08 → OK

  Format byte:          0x05
  ICC Dynamic Number:   3B9A12F0
  Hash in SDAD:         8F3A21C0D4E5B6F7...
  Expected hash:        8F3A21C0D4E5B6F7...
  Hash check:           OK

  ✓ VERIFICATION PASSED
  ✓ Message authentically signed by cardholder: 'LAST/FIRST I'
```

If the message or cardholder field has been tampered with, the commitment check
fails before the SDAD is even checked:

```
  Commitment check: SHA256(message + cardholder)[:4] = A3F21C08 → FAIL
  ✗ COMMITMENT MISMATCH — message or cardholder has been tampered with
```

### Supplying the public key separately

Older bundles (or bundles generated without an embedded key) can still be
verified by passing the PEM file explicitly:

```sh
# Linux — export requires card; verify does not
./emv-pki.py export --output card.pem
./emv-pki.py verify --signature approval.json --pubkey card.pem
```

```cmd
rem Windows
uv run emv-pki.py export --output card.pem
uv run emv-pki.py verify --signature approval.json --pubkey card.pem
```

---

## Signing without a message

Omitting `--message` still signs and still embeds the cardholder and ICC public
key.  The Unpredictable Number is random, so each signature is unique:

```sh
./emv-pki.py sign --output sig.json          # Linux
uv run emv-pki.py sign --output sig.json     # Windows
```

This is useful as a proof-of-card-presence timestamp rather than a message
attestation.

---

## Exporting the ICC public key

To extract the card's RSA public key as a PEM file for use in other tools:

```sh
./emv-pki.py export --output card.pem          # Linux
uv run emv-pki.py export --output card.pem      # Windows
```

The key is recovered by decoding the full certificate chain embedded in the
card (CA → Issuer PK → ICC PK) using the publicly known EMV CA root keys.

---

## Encryption and decryption (experimental, limited card support)

The tool can encrypt data **to** a card's ICC public key using a hybrid scheme
(RSA-OAEP-SHA256 + AES-256-GCM):

```sh
./emv-pki.py encrypt --message "secret data" --output encrypted.json
./emv-pki.py encrypt --input file.txt --output encrypted.json
```

Decryption requires the card to perform the RSA private operation via the
ISO 7816-8 `PSO:DECIPHER` command:

```sh
./emv-pki.py decrypt --input encrypted.json
```

**However, most payment cards refuse `PSO:DECIPHER`.**  The EMV specification
does not require cards to implement it, and in practice almost all Visa and
Mastercard chips return `6D00` (instruction not supported) or `6985` (conditions
not satisfied).  The `sign` command works reliably because INTERNAL AUTHENTICATE
is a standard DDA requirement.

**Recommendation:** Use the card for signing only.  For encryption to a
cardholder's identity, export the ICC public key (`export` command) and use a
dedicated tool:

- **age** — `age -r "$(ssh-keygen -e -f card.pem)"` — simple file encryption
- **OpenSSL** — `openssl pkeyutl -encrypt -pubin -inkey card.pem`
- **GPG** — import the key and use normal GPG asymmetric encryption

The recipient would then need a working `PSO:DECIPHER` card (rare) or a
separately stored private key to decrypt — neither of which this tool can
reliably provide.  For practical encrypted messaging tied to a cardholder
identity, use the signature to authenticate and a conventional key exchange
(e.g. ECDH) for confidentiality.

---

## Other commands

| Command  | Description |
|----------|-------------|
| `info`   | Display network, cardholder, PAN (masked), expiry, AIP flags, and certificate chain decode status |
| `raw`    | Dump every raw TLV tag read from the card — useful for diagnostics |
| `export` | Export the ICC public key as a PEM file |
| `probe`  | Send every known crypto APDU and report the card's SW responses — shows exactly what the card supports |

### Probe example

```sh
./emv-pki.py probe          # Linux
uv run emv-pki.py probe     # Windows
```

```
  Command                                SW      Response / Notes
  ────────────────────────────────────── ──────  ──────────────────────────────
  INTERNAL AUTHENTICATE (4-byte UN)      9000    OK — SDAD 144 bytes
  PSO:DECIPHER (RSA key unwrap)          6D00    INS not supported
  PSO:HASH                               6D00    INS not supported
  GENERATE AC (ARQC)                     9000    OK
  ...
```

---

## Global options

```
--reader N     Use reader at index N (default: 0). Use --verbose to list available readers.
--verbose, -v  Print raw APDUs and TLV parsing details.
--json         Also emit raw JSON output at the end of info/export commands.
```

---

## Windows troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `SCARD_E_NO_SERVICE` or `SCARD_E_SERVICE_STOPPED` | The smart card service shut down after the last reader was removed | Plug in the reader and run the command again; the service restarts automatically |
| `No module named 'smartcard'` | `uv` not used to run the script | Use `uv run emv-pki.py` instead of `python emv-pki.py` |
| Reader not detected | Device still initialising after plug-in | Wait a few seconds for Windows to install the CCID driver, then retry |
| Two readers visible (`--verbose`) | Reader has two slots or a contactless antenna | Use `--reader 0` or `--reader 1` to select the correct slot |

---

## Security notes

- The card's **private key never leaves the chip**.  The tool only sends data
  *to* the card and receives the signed output.
- The SDAD produced by INTERNAL AUTHENTICATE is a one-time signature; replaying
  it proves nothing about a new message.  The commitment scheme used here ties
  each SDAD to a specific message+cardholder pair.
- The ICC public key is recovered from the card's certificate chain using
  publicly known CA root keys — the same trust anchors used by payment terminals.
  A recovered key whose chain validates correctly was issued by the card network
  and is tied to the physical card.
- The cardholder name is read from the card's chip (EMV tag 5F20) and embedded
  in the signature bundle unmodified.  Altering it after signing breaks the
  commitment check.
