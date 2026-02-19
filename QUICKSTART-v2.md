# EMV-PKI v2.0 Quick Start Guide

**Hardened Multi-Round Signing**

---

## Basic Usage

### Sign a Message (Default: 3 rounds, ~1.5 seconds)

```bash
./emv-pki.py sign --message "I approve this transaction" --output approval.json
```

**Output:**
```
━━━ Sign Data with Card (Multi-Round Hardened) ━━━━━━━━━━
  Cardholder:  DOE/JOHN
  Rounds:      3 (2^96 collision resistance)
  Nonce:       F4A8B2C1... (prevents replay)
  Timestamp:   2026-02-19T12:34:56Z
  Message:     'I approve this transaction'

  Performing 3 signing rounds...
    Round 1/3: commitment=3F8A2C01
    Round 2/3: commitment=7B4D9E3A
    Round 3/3: commitment=C2F1A857
  ✓ All 3 rounds completed and verified

  Saved to: approval.json
  Security: 3 rounds = 2^96-bit collision resistance
```

---

### Verify a Signature (No card needed)

```bash
./emv-pki.py verify --signature approval.json
```

**Output:**
```
━━━ Verify Signature ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Version:     2
  Algorithm:   EMV-DDA-MULTI-ROUND
  Security:    3-round (2^96 collision resistance)

  ── Certificate Chain Re-Validation ──
  ✓ Certificate chain validated against known CA keys
  ✓ ICC public key matches chain-recovered key

  ── Verifying 3 Signing Rounds ──
    Round 1: ✓ commitment + SDAD verified
    Round 2: ✓ commitment + SDAD verified
    Round 3: ✓ commitment + SDAD verified

  ✓ ALL 3 ROUNDS VERIFIED
  ✓ Certificate chain authenticated
  ✓ Message authentically signed by cardholder: 'DOE/JOHN'
  ✓ Security: 2^96-bit collision resistance
```

---

## Security Levels

### Minimum Secure (2 rounds, ~1 second)

```bash
./emv-pki.py sign --message "Quick auth token" --rounds 2
```

**Security:** 2^64 collision resistance (~584 million years @ 10 GH/s)
**Use case:** Interactive authentication, time-sensitive operations

---

### Default Recommended (3 rounds, ~1.5 seconds)

```bash
./emv-pki.py sign --message "Standard document" --rounds 3
```

**Security:** 2^96 collision resistance (computationally infeasible)
**Use case:** General document signing, contracts, approvals ✅ **DEFAULT**

---

### High Assurance (5 rounds, ~2.5 seconds)

```bash
./emv-pki.py sign --message "High-value contract" --rounds 5
```

**Security:** 2^160 collision resistance (exceeds age of universe)
**Use case:** High-value financial transactions, legal contracts

---

### Maximum Paranoid (10 rounds, ~5 seconds)

```bash
./emv-pki.py sign --message "Ultra-critical operation" --rounds 10
```

**Security:** 2^320 collision resistance (theoretical overkill)
**Use case:** Nation-state threat model, maximum assurance

---

## Command Reference

### Card Information

```bash
# Show card details and capabilities
./emv-pki.py info

# Export ICC public key as PEM
./emv-pki.py export --output card.pem

# Test all crypto capabilities
./emv-pki.py probe

# Dump all raw TLV data
./emv-pki.py raw
```

---

### Signing Options

```bash
# Sign with custom output path
./emv-pki.py sign --message "text" --output /path/to/sig.json

# Sign without message (card presence proof)
./emv-pki.py sign --rounds 3 --output presence.json

# Choose specific reader (if multiple)
./emv-pki.py sign --message "text" --reader 1

# Verbose mode (show APDUs)
./emv-pki.py sign --message "text" --verbose
```

---

## Security Features (v2.0)

### ✅ Message Forgery Protection

**Attack difficulty:** 2^(32 × rounds)
- 1 round: 2^32 (~0.4 seconds) ❌ **INSECURE**
- 2 rounds: 2^64 (~584 million years) ✅ **MINIMUM**
- 3 rounds: 2^96 (~10^19 years) ✅✅ **RECOMMENDED**
- 5 rounds: 2^160 (~10^38 years) ✅✅✅ **MAXIMUM**

### ✅ Key Substitution Prevention

Certificate chain re-validation ensures:
- ICC public key was issued by legitimate card issuer
- Key cannot be substituted without forging EMV certificates
- Chain validated against compiled CA root keys

### ✅ Replay Attack Prevention

Random 16-byte nonce ensures:
- Each signature is unique
- Old signatures can be detected via nonce tracking
- Same message signed twice → different signatures

### ✅ Timestamp Integrity

Timestamp bound to commitment:
- Cannot be changed without breaking signature
- Proves time of signing (within system clock accuracy)
- Application should validate timestamp is reasonable

---

## Migration from v1.0

### Verifying Old Signatures

v1 signatures still work with warnings:

```bash
./emv-pki.py verify --signature old_v1_signature.json
```

**Output:**
```
⚠  WARNING: This is a legacy Version 1 signature (single-round)
   Version 1 signatures are vulnerable to:
     - W1: 32-bit collision (message forgery in ~0.4s)
     - W2: Key substitution (if chain not validated)
     - W4: Timestamp tampering
     - W5: Replay attacks
   Recommend re-signing with --rounds 3 or higher

✓ VERIFICATION PASSED (legacy format)
```

### Re-Signing for v2 Security

```bash
# Re-sign with hardened format
./emv-pki.py sign --message "same message" --rounds 3 --output new_v2.json

# Verify with full protection
./emv-pki.py verify --signature new_v2.json
```

---

## Performance Comparison

| Rounds | Time  | Bundle Size | Security (@ 10 GH/s) |
|--------|-------|-------------|----------------------|
| 1      | 0.5s  | ~1.5 KB     | 0.4 seconds ❌       |
| 2      | 1.0s  | ~1.8 KB     | 584 million years ✅  |
| 3      | 1.5s  | ~2.0 KB     | 10^19 years ✅✅      |
| 5      | 2.5s  | ~2.5 KB     | 10^38 years ✅✅✅    |
| 10     | 5.0s  | ~3.5 KB     | 10^86 years 🤯        |

---

## Bundle Structure (v2)

```json
{
  "version": "2",
  "algorithm": "EMV-DDA-MULTI-ROUND",
  "security_level": "3-round (2^96 collision resistance)",
  "rounds": 3,
  "network": "Visa",
  "cardholder": "DOE/JOHN",
  "message": "I approve this transaction",
  "timestamp": "2026-02-19T12:34:56.789Z",
  "nonce": "F4A8B2C1D7E93B6A...",
  "signing_rounds": [
    {
      "round": 0,
      "auth_data": "3f8a2c01",
      "sdad": "base64_encoded_signature...",
      "full_commitment_hash": "sha256_hex...",
      "icc_dynamic_number": "4b7d9e2f"
    },
    // rounds 1, 2 ...
  ],
  "certificate_chain": {
    "ca_key_index": "09",
    "issuer_pk_cert": "hex...",
    "icc_pk_cert": "hex...",
    // full chain data
  },
  "icc_public_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
}
```

---

## Troubleshooting

### "Card did not respond to INTERNAL AUTHENTICATE"

**Cause:** Card doesn't support DDA (Dynamic Data Authentication)
**Solution:** Card will fall back to GENERATE AC mode automatically

### "Expected N rounds, got M"

**Cause:** Bundle tampered with or corrupted
**Solution:** Re-verify from original bundle

### "Embedded ICC public key does NOT match certificate chain"

**Cause:** **SECURITY VIOLATION** — key substitution attack detected
**Solution:** Reject signature, investigate source

### "COMMITMENT HASH MISMATCH"

**Cause:** Message, cardholder, timestamp, or nonce was modified
**Solution:** Reject signature — tampering detected

---

## Best Practices

### Application Integration

1. **Store used nonces** to prevent replay attacks:
   ```python
   if sig_bundle['nonce'] in used_nonces_db:
       raise ReplayAttackDetected()
   ```

2. **Validate timestamp** is reasonable:
   ```python
   sig_time = parse_iso8601(sig_bundle['timestamp'])
   if abs(now - sig_time) > timedelta(minutes=5):
       raise TimestampOutOfBounds()
   ```

3. **Verify cardholder** is authorized:
   ```python
   if sig_bundle['cardholder'] not in authorized_signers:
       raise UnauthorizedSigner()
   ```

4. **Use structured messages** for high-value operations:
   ```python
   message = json.dumps({
       'action': 'transfer',
       'amount': 10000,
       'to': 'account123',
       'id': uuid4()
   })
   ```

---

## Support

- **Documentation:** `readme.md`, `weaknesses.md`, `HARDENING.md`
- **Security issues:** See `weaknesses.md` for known limitations
- **Card compatibility:** Run `./emv-pki.py info` to check capabilities

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────┐
│ EMV-PKI v2.0 — Security Hardened                   │
├─────────────────────────────────────────────────────┤
│ SIGN:   ./emv-pki.py sign -m "msg" -r 3            │
│ VERIFY: ./emv-pki.py verify -s sig.json            │
├─────────────────────────────────────────────────────┤
│ Security Levels:                                    │
│   --rounds 2  → 2^64   (~1s)   [minimum]           │
│   --rounds 3  → 2^96   (~1.5s) [DEFAULT]           │
│   --rounds 5  → 2^160  (~2.5s) [maximum]           │
├─────────────────────────────────────────────────────┤
│ Protection:                                         │
│   ✓ Message forgery  → 2^(32×rounds) difficulty    │
│   ✓ Key substitution → Chain re-validation         │
│   ✓ Replay attacks   → Unique nonce tracking       │
│   ✓ Timestamp tamper → Bound in commitment         │
└─────────────────────────────────────────────────────┘
```
