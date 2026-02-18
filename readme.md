# emv-pki

Use an EMV chip card (Visa, Mastercard, Amex, etc.) as a hardware security token
to sign messages and verify signatures.  The card's private key never leaves the
chip — it is used only through the card's own INTERNAL AUTHENTICATE command.

**All operations that touch the card require a real card in a reader.**
Verification of an existing signature requires no card at all.

---

## Requirements

- A PC/SC-compliant **contact** smart card reader (ACR1252U, SCM SCR3310, etc.)
- Linux with `pcscd` running:
  ```
  sudo systemctl start pcscd
  ```
- Python 3.12+ with [uv](https://github.com/astral-sh/uv) — dependencies are
  declared inline and installed automatically:
  ```
  pip install uv        # one-time
  ```

No other setup is needed.  Run the script directly:

```
./emv-pki.py <command> [options]
```

---

## Card compatibility

The sign command requires Dynamic Data Authentication (DDA), which gives the card
a unique RSA private key per-chip.  Run `info` to check whether your card
supports it:

```
$ ./emv-pki.py info
```

```
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

```
./emv-pki.py sign --message "I approve this transaction" --output approval.json
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

No card is needed.  The ICC public key is embedded in the signature bundle.

```
./emv-pki.py verify --signature approval.json
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

```
./emv-pki.py export --output card.pem          # requires card
./emv-pki.py verify --signature approval.json --pubkey card.pem
```

---

## Signing without a message

Omitting `--message` still signs, and still embeds the cardholder and ICC public
key.  The Unpredictable Number is random, so each signature is unique and
non-deterministic:

```
./emv-pki.py sign --output sig.json
```

This is useful as a proof-of-card-presence timestamp rather than a message
attestation.

---

## Exporting the ICC public key

To extract the card's RSA public key as a PEM file for use in other tools:

```
./emv-pki.py export --output card.pem
```

The key is recovered by decoding the full certificate chain embedded in the
card (CA → Issuer PK → ICC PK) using the publicly known EMV CA root keys.

---

## Encryption and decryption (experimental, limited card support)

The tool can encrypt data **to** a card's ICC public key using a hybrid scheme
(RSA-OAEP-SHA256 + AES-256-GCM):

```
./emv-pki.py encrypt --message "secret data" --output encrypted.json
./emv-pki.py encrypt --input file.txt --output encrypted.json
```

Decryption requires the card to perform the RSA private operation via the
ISO 7816-8 `PSO:DECIPHER` command:

```
./emv-pki.py decrypt --input encrypted.json
```

**However, most payment cards refuse `PSO:DECIPHER`.**  The EMV specification
does not require cards to implement it, and in practice almost all Visa and
Mastercard chips return `6D00` (instruction not supported) or `6985` (conditions
not satisfied).  The `sign` command works reliably because INTERNAL AUTHENTICATE
is a standard DDA requirement.

**Recommendation:** Use the card for signing only.  For encryption to a
card-holder's identity, export the ICC public key (`export` command) and use a
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

| Command | Description |
|---------|-------------|
| `info`  | Display network, cardholder, PAN (masked), expiry, AIP flags, and certificate chain decode status |
| `raw`   | Dump every raw TLV tag read from the card — useful for diagnostics |
| `export` | Export the ICC public key as a PEM file |
| `probe` | Send every known crypto APDU and report the card's SW responses — shows exactly what the card supports |

### Probe example

```
./emv-pki.py probe
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
--reader N     Use reader at index N (default: 0). List readers with --verbose.
--verbose, -v  Print raw APDUs and TLV parsing details.
--json         Also emit raw JSON output at the end of info/export commands.
```

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
