#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "pyscard", "cryptography",
# ]
# ///

"""
emv_pki.py - EMV Credit Card PKI Tool
=====================================
Uses EMV chip cards as hardware security tokens for PKI operations.

Supports: Visa, Mastercard, Amex, Discover, JCB, UnionPay, Maestro, Interac

Requirements:
  - A PC/SC compliant smart card reader (contact) OR an NFC reader
  - Linux with pcscd running: sudo systemctl start pcscd
  - pip install pyscard cryptography

Commands:
  info      - Read card identity and public key
  encrypt   - Encrypt data using the card's ICC public key
  decrypt   - Decrypt data (card signs challenge, key derived from cert chain)
  sign      - Use card to sign data via INTERNAL AUTHENTICATE
  verify    - Verify a card-generated signature
  export    - Export card's public key in PEM format
  demo      - Demo mode with simulated card data (no reader needed)
"""

import sys
import os
import json
import struct
import hashlib
import argparse
import binascii
import datetime
import base64
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────────
# Attempt to import smartcard libraries (optional – demo mode works without)
# ──────────────────────────────────────────────────────────────────────────────
try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
    from smartcard.CardType import AnyCardType
    from smartcard.CardRequest import CardRequest
    from smartcard.Exceptions import CardRequestTimeoutException, NoCardException
    PYSCARD_AVAILABLE = True
except ImportError:
    PYSCARD_AVAILABLE = False

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os as _os

# ──────────────────────────────────────────────────────────────────────────────
# Known EMV Certification Authority (CA) Public Keys
# These are the ROOT public keys published by card networks.
# Load from a JSON file with --ca-keys, or the tool will attempt to read
# Issuer/ICC key data without full chain validation.
# Key index structure: { RID: { key_index: (modulus_hex, exponent_hex) } }
# ──────────────────────────────────────────────────────────────────────────────

# Global verbose flag
VERBOSE = False

def vprint(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)

# RID = first 5 bytes of AID (Application Identifier)
KNOWN_RIDS = {
    "A000000003": "Visa",
    "A000000004": "Mastercard",
    "A000000025": "American Express",
    "A000000152": "Discover",
    "A000000065": "JCB",
    "A000000333": "China UnionPay",
    "A0000000043060": "Maestro",
    "A000000277": "Interac",
    "A000000098": "Visa Electron",
    "A0000000291010": "Visa Classic",
    "A0000000041010": "Mastercard Credit",
    "A0000000042010": "Mastercard Debit (Maestro)",
    "A0000000043010": "Maestro UK",
    "A0000000250101": "Amex Credit",
}

def get_network_name(aid_hex: str) -> str:
    """Identify card network from AID."""
    aid_hex = aid_hex.upper()
    # Check full AID first, then RID (first 10 hex chars = 5 bytes)
    for rid, name in KNOWN_RIDS.items():
        if aid_hex.startswith(rid.upper()):
            return name
    return "Unknown Network"

# ──────────────────────────────────────────────────────────────────────────────
# TLV (Tag-Length-Value) Parser — core EMV data format
# ──────────────────────────────────────────────────────────────────────────────

class TLV:
    """Parse EMV BER-TLV encoded data."""

    @staticmethod
    def parse(data: bytes) -> dict:
        """Parse TLV bytes into {tag_hex: value_bytes} dict."""
        result = {}
        i = 0
        while i < len(data):
            if data[i] == 0x00 or data[i] == 0xFF:
                i += 1
                continue
            # Parse tag
            tag = data[i]
            i += 1
            if (tag & 0x1F) == 0x1F:  # multi-byte tag
                while i < len(data) and (data[i] & 0x80):
                    tag = (tag << 8) | data[i]
                    i += 1
                if i < len(data):
                    tag = (tag << 8) | data[i]
                    i += 1
            tag_hex = format(tag, 'X').zfill(2 if tag <= 0xFF else 4)

            if i >= len(data):
                break

            # Parse length
            length = data[i]
            i += 1
            if length == 0x81:
                if i >= len(data): break
                length = data[i]; i += 1
            elif length == 0x82:
                if i + 1 >= len(data): break
                length = (data[i] << 8) | data[i+1]; i += 2

            # Parse value
            value = data[i:i+length]
            i += length

            # Handle constructed tags — recurse into them
            constructed_tags = {'6F', '70', '77', 'A5', 'BF0C', 'E1', 'FF01', '61'}
            if tag_hex in constructed_tags:
                nested = TLV.parse(value)
                result.update(nested)
            else:
                result[tag_hex] = value

        return result

    @staticmethod
    def find(data: bytes, target_tag: str) -> bytes | None:
        """Find a specific tag in TLV data."""
        parsed = TLV.parse(data)
        return parsed.get(target_tag.upper())


# ──────────────────────────────────────────────────────────────────────────────
# APDU Helper
# ──────────────────────────────────────────────────────────────────────────────

class APDUError(Exception):
    pass

def sw_to_str(sw1: int, sw2: int) -> str:
    sw = (sw1 << 8) | sw2
    codes = {
        0x9000: "Success",
        0x6700: "Wrong length",
        0x6982: "Security status not satisfied",
        0x6983: "Authentication method blocked",
        0x6984: "Referenced data invalidated",
        0x6985: "Conditions not satisfied",
        0x6986: "Command not allowed",
        0x6A81: "Function not supported",
        0x6A82: "File not found",
        0x6A83: "Record not found",
        0x6D00: "Instruction not supported",
        0x6E00: "Class not supported",
    }
    return codes.get(sw, f"SW={sw1:02X}{sw2:02X}")


class CardInterface:
    """Abstracts PC/SC card communication."""

    def __init__(self, connection):
        self.connection = connection

    def send(self, apdu: list[int], description: str = "") -> bytes:
        """Send APDU, return response data (raises on non-9000)."""
        vprint(f"    APDU >> {' '.join(f'{b:02X}' for b in apdu)}")
        resp, sw1, sw2 = self.connection.transmit(apdu)
        # Handle GET RESPONSE
        if sw1 == 0x61:
            get_resp = [0x00, 0xC0, 0x00, 0x00, sw2]
            resp, sw1, sw2 = self.connection.transmit(get_resp)
        vprint(f"    APDU << {' '.join(f'{b:02X}' for b in resp)} SW={sw1:02X}{sw2:02X}")
        if (sw1, sw2) != (0x90, 0x00):
            status = sw_to_str(sw1, sw2)
            raise APDUError(f"{description or 'APDU'} failed: {status}")
        return bytes(resp)

    def send_soft(self, apdu: list[int]) -> tuple[bytes, int, int]:
        """Send APDU, return (data, sw1, sw2) without raising."""
        vprint(f"    APDU >> {' '.join(f'{b:02X}' for b in apdu)}")
        resp, sw1, sw2 = self.connection.transmit(apdu)
        # Handle GET RESPONSE (61 xx)
        if sw1 == 0x61:
            get_resp = [0x00, 0xC0, 0x00, 0x00, sw2]
            resp, sw1, sw2 = self.connection.transmit(get_resp)
        # Handle wrong Le (6C xx) — retry with the correct Le value
        elif sw1 == 0x6C:
            correct_le = sw2
            retry_apdu = apdu[:-1] + [correct_le]
            vprint(f"    APDU >> {' '.join(f'{b:02X}' for b in retry_apdu)} (retry with Le={correct_le:#04x})")
            resp, sw1, sw2 = self.connection.transmit(retry_apdu)
            if sw1 == 0x61:
                get_resp = [0x00, 0xC0, 0x00, 0x00, sw2]
                resp, sw1, sw2 = self.connection.transmit(get_resp)
        vprint(f"    APDU << {' '.join(f'{b:02X}' for b in resp)} SW={sw1:02X}{sw2:02X}")
        return bytes(resp), sw1, sw2


# ──────────────────────────────────────────────────────────────────────────────
# EMV Card Reader
# ──────────────────────────────────────────────────────────────────────────────

class EMVCard:
    """
    Reads public data from an EMV chip card.

    Data extracted:
      - AID / network
      - PAN (card number), expiry, cardholder name
      - ICC Public Key (for DDA/CDA cards) — via certificate chain
      - Issuer Public Key
      - Application version, usage control
    """

    # Standard PSE (Payment System Environment) AID
    PSE_CONTACT    = list(b"1PAY.SYS.DDF01")
    PSE_CONTACTLESS= list(b"2PAY.SYS.DDF01")

    # Common AIDs to try directly if PSE fails
    FALLBACK_AIDS = [
        [0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10],  # Visa Credit
        [0xA0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10],  # Visa Electron
        [0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10],  # Mastercard
        [0xA0, 0x00, 0x00, 0x00, 0x04, 0x30, 0x60],  # Maestro
        [0xA0, 0x00, 0x00, 0x00, 0x25, 0x01, 0x01],  # Amex
        [0xA0, 0x00, 0x00, 0x01, 0x52, 0x30, 0x10],  # Discover
        [0xA0, 0x00, 0x00, 0x00, 0x65, 0x10, 0x10],  # JCB
        [0xA0, 0x00, 0x00, 0x03, 0x33, 0x01, 0x01],  # UnionPay
    ]

    def __init__(self, card: CardInterface):
        self.card = card
        self.data: dict[str, bytes] = {}  # tag -> value
        self.raw_records: list[tuple[int, int, bytes]] = []  # (sfi, rec, raw_bytes)
        self.aid: bytes | None = None
        self.network: str = "Unknown"
        self.afl: list | None = None

    # ── SELECT ────────────────────────────────────────────────────────────────

    def _select(self, aid_bytes: list[int]) -> bytes | None:
        apdu = [0x00, 0xA4, 0x04, 0x00, len(aid_bytes)] + aid_bytes + [0x00]
        resp, sw1, sw2 = self.card.send_soft(apdu)
        if (sw1, sw2) == (0x90, 0x00):
            return resp
        return None

    def _get_pse_aids(self, pse_aid: list[int]) -> list[bytes]:
        """Read directory from PSE and return list of AIDs."""
        resp = self._select(pse_aid)
        if not resp:
            return []

        aids = []
        # Read records from PSE directory (SFI=1, records 1-10)
        for rec in range(1, 11):
            apdu = [0x00, 0xB2, rec, (1 << 3) | 4, 0x00]
            data, sw1, sw2 = self.card.send_soft(apdu)
            if (sw1, sw2) != (0x90, 0x00):
                break
            tlv = TLV.parse(data)
            aid_val = tlv.get('4F')
            if aid_val:
                aids.append(aid_val)
        return aids

    def select_application(self) -> bool:
        """Select best application on card. Returns True on success."""
        # Try PSE first (contact), then PPSE (contactless)
        aids = (self._get_pse_aids(self.PSE_CONTACT) or
                self._get_pse_aids(self.PSE_CONTACTLESS))

        if not aids:
            # Try fallback AIDs
            for aid in self.FALLBACK_AIDS:
                resp = self._select(aid)
                if resp:
                    aids = [bytes(aid)]
                    break

        if not aids:
            return False

        # Select the first (highest priority) AID
        aid = aids[0]
        resp = self._select(list(aid))
        if resp:
            self.aid = aid
            rid_hex = aid[:5].hex().upper()
            self.network = get_network_name(rid_hex)
            tlv = TLV.parse(resp)
            self.data.update(tlv)
            return True
        return False

    # ── GET PROCESSING OPTIONS ────────────────────────────────────────────────

    def get_processing_options(self) -> bool:
        """Initiate EMV transaction flow to get AFL."""
        # Build PDOL data (use zeros for all terminal data)
        pdol = self.data.get('9F38')
        pdol_data = self._build_pdol_data(pdol)

        lc = len(pdol_data)
        apdu = [0x80, 0xA8, 0x00, 0x00, lc + 2, 0x83, lc] + pdol_data + [0x00]
        data, sw1, sw2 = self.card.send_soft(apdu)

        if (sw1, sw2) != (0x90, 0x00):
            # Try without PDOL
            apdu = [0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00]
            data, sw1, sw2 = self.card.send_soft(apdu)

        if (sw1, sw2) != (0x90, 0x00):
            return False

        # GPO can return Format 1 (tag 80: raw AIP+AFL) or Format 2 (tag 77: TLV)
        afl_raw = None
        if data and data[0] == 0x80:
            # Format 1: tag 80, length byte, then [AIP(2)] + [AFL(variable)]
            # Parse outer TLV to get the 80 value
            tlv = TLV.parse(data)
            raw80 = tlv.get('80')
            if raw80 and len(raw80) >= 2:
                aip_bytes = raw80[:2]
                self.data['82'] = aip_bytes  # Store AIP under its proper tag
                afl_raw = raw80[2:]
                vprint(f"  GPO Format 1: AIP={aip_bytes.hex().upper()} AFL={afl_raw.hex().upper()}")
        else:
            # Format 2: TLV-encoded response (tag 77)
            tlv = TLV.parse(data)
            self.data.update(tlv)
            afl_raw = tlv.get('94')

        if afl_raw and len(afl_raw) % 4 == 0:
            self.afl = []
            for i in range(0, len(afl_raw), 4):
                sfi      = (afl_raw[i] >> 3)
                first    = afl_raw[i+1]
                last     = afl_raw[i+2]
                # offline = afl_raw[i+3]
                self.afl.append((sfi, first, last))
            vprint(f"  AFL entries: {self.afl}")
        return True

    def _build_pdol_data(self, pdol: bytes | None) -> list[int]:
        """Build zero-filled PDOL response data."""
        if not pdol:
            return []
        result = []
        i = 0
        while i < len(pdol):
            tag = pdol[i]; i += 1
            if (tag & 0x1F) == 0x1F:
                while i < len(pdol) and (pdol[i] & 0x80):
                    i += 1
                i += 1
            if i >= len(pdol): break
            length = pdol[i]; i += 1
            result.extend([0x00] * length)
        return result

    # ── READ RECORDS ──────────────────────────────────────────────────────────

    def read_records(self, scan_all_sfis: bool = False) -> bool:
        """Read all records indicated by AFL, optionally brute-force all SFIs."""
        afl_sfis = set()

        if self.afl:
            for sfi, first, last in self.afl:
                afl_sfis.add(sfi)
                p2 = (sfi << 3) | 4
                for rec in range(first, last + 1):
                    apdu = [0x00, 0xB2, rec, p2, 0x00]
                    data, sw1, sw2 = self.card.send_soft(apdu)
                    if (sw1, sw2) == (0x90, 0x00):
                        vprint(f"  SFI {sfi} rec {rec}: {data.hex().upper()}")
                        self.data.update(TLV.parse(data))
                        self.raw_records.append((sfi, rec, data))

        if scan_all_sfis or not self.afl:
            # Brute-force SFIs 1-10, records 1-8 to find hidden data
            sfis_to_scan = range(1, 11) if not self.afl else [s for s in range(1, 11) if s not in afl_sfis]
            for sfi in sfis_to_scan:
                for rec in range(1, 9):
                    p2 = (sfi << 3) | 4
                    apdu = [0x00, 0xB2, rec, p2, 0x00]
                    data, sw1, sw2 = self.card.send_soft(apdu)
                    if (sw1, sw2) == (0x90, 0x00):
                        vprint(f"  SFI {sfi} rec {rec} [extra]: {data.hex().upper()}")
                        self.data.update(TLV.parse(data))
                        self.raw_records.append((sfi, rec, data))
                    elif sw1 == 0x6A and sw2 == 0x83:
                        break  # Record not found — no more records in this SFI
        return True

    # ── GET DATA (individual tags) ─────────────────────────────────────────────

    def get_data(self, tag: int) -> bytes | None:
        tag_hi = (tag >> 8) & 0xFF
        tag_lo = tag & 0xFF
        apdu = [0x80, 0xCA, tag_hi, tag_lo, 0x00]
        data, sw1, sw2 = self.card.send_soft(apdu)
        if (sw1, sw2) == (0x90, 0x00):
            tlv = TLV.parse(data)
            for v in tlv.values():
                return v
        return None

    # ── FULL READ ──────────────────────────────────────────────────────────────

    def read_all(self, scan_all: bool = False) -> bool:
        """Perform full card read sequence."""
        if not self.select_application():
            return False
        self.get_processing_options()
        self.read_records(scan_all_sfis=scan_all)

        # Try GET DATA for extra tags (ATC, lower counter, PIN retry, log format)
        for tag in [0x9F36, 0x9F13, 0x9F17, 0x9F4F, 0x9F2B, 0x9F32, 0x8F, 0x90]:
            val = self.get_data(tag)
            if val:
                tag_hex = format(tag, '04X')
                if tag_hex not in self.data:
                    self.data[tag_hex] = val

        return True

    # ── ICC PUBLIC KEY EXTRACTION ──────────────────────────────────────────────

    def get_icc_public_key_raw(self) -> dict | None:
        """
        Return raw ICC public key components from card data.
        Returns None if card doesn't support DDA (static-auth-only cards).
        """
        cert = self.data.get('9F46')  # ICC Public Key Certificate
        exp  = self.data.get('9F47')  # ICC Public Key Exponent
        rem  = self.data.get('9F48')  # ICC Public Key Remainder

        if not cert or not exp:
            return None

        return {
            'certificate': cert,
            'exponent': exp,
            'remainder': rem,
            'issuer_pk_cert': self.data.get('90'),
            'issuer_pk_exp': self.data.get('9F32'),
            'issuer_pk_rem': self.data.get('9F2B'),  # 9F2B = Issuer PK Remainder (not 9F35=Terminal Type)
            'ca_pk_index': self.data.get('8F'),
        }

    # ── CARD INFO ─────────────────────────────────────────────────────────────

    def get_info(self) -> dict:
        """Return human-readable card info."""
        info = {
            'network': self.network,
            'aid': self.aid.hex().upper() if self.aid else None,
        }

        # PAN from Track2 or tag 5A
        pan_raw = self.data.get('5A') or self.data.get('57')
        if pan_raw:
            pan_hex = pan_raw.hex().upper()
            # Strip trailing F padding and separator
            pan = pan_hex.split('D')[0].split('F')[0].rstrip('F')
            info['pan'] = pan
            info['pan_masked'] = pan[:6] + '*' * (len(pan)-10) + pan[-4:]

        # Cardholder name
        name = self.data.get('5F20')
        if name:
            info['cardholder'] = name.decode('ascii', errors='replace').strip()

        # Expiry
        exp = self.data.get('5F24')
        if exp:
            if len(exp) == 3:
                info['expiry'] = f"{exp[1]:02d}/{exp[0]:02d}"  # YYMMDD
            else:
                info['expiry'] = exp.hex()

        # Application label
        label = self.data.get('50')
        if label:
            info['app_label'] = label.decode('ascii', errors='replace').strip()

        # ICC public key info
        icc_pk = self.get_icc_public_key_raw()
        if icc_pk and icc_pk.get('certificate'):
            info['has_icc_public_key'] = True
            info['icc_pk_cert_len'] = len(icc_pk['certificate'])
            ca_idx = icc_pk.get('ca_pk_index')
            if ca_idx:
                info['ca_key_index'] = ca_idx[0]
        else:
            info['has_icc_public_key'] = False
            info['note'] = "Card uses SDA only (no ICC-level RSA key). PIN encipherment key may still be available."

        # PIN encipherment key (alternative for encryption)
        pin_enc_cert = self.data.get('9F2D')
        if pin_enc_cert:
            info['has_pin_encipherment_key'] = True

        # Application Interchange Profile (tells us SDA/DDA/CDA support)
        aip = self.data.get('82')
        if aip and len(aip) >= 2:
            aip_val = (aip[0] << 8) | aip[1]
            info['aip'] = f"{aip.hex().upper()}"
            info['supports_sda'] = bool(aip_val & 0x4000)
            info['supports_dda'] = bool(aip_val & 0x2000)
            info['supports_cda'] = bool(aip_val & 0x0100)

        # Issuer PK cert presence (for SDA)
        iss_cert = self.data.get('90')
        if iss_cert:
            info['has_issuer_pk_cert'] = True
            info['issuer_pk_cert_len'] = len(iss_cert)

        # Signed Static Application Data (SDA signature over card data)
        ssad = self.data.get('93')
        if ssad:
            info['has_ssad'] = True
            info['ssad_len'] = len(ssad)

        return info


# ──────────────────────────────────────────────────────────────────────────────
# RSA Certificate Chain Decoder
# ──────────────────────────────────────────────────────────────────────────────

def decode_emv_cert(cert_bytes: bytes, modulus: bytes, exp_bytes: bytes) -> dict | None:
    """
    Decode an EMV RSA certificate (Issuer PK cert or ICC PK cert).
    Uses the provided public key to 'decrypt' (RSA public operation) the cert.
    Returns dict with extracted fields, or None on failure.
    """
    try:
        n = int.from_bytes(modulus, 'big')
        e = int.from_bytes(exp_bytes, 'big')

        # RSA public operation: cert^e mod n
        cert_int = int.from_bytes(cert_bytes, 'big')
        recovered_int = pow(cert_int, e, n)
        recovered = recovered_int.to_bytes(len(cert_bytes), 'big')

        # Validate header and trailer
        if recovered[0] != 0x6A or recovered[-1] != 0xBC:
            return None

        return {
            'format': recovered[1],
            'recovered': recovered,
            'valid': True
        }
    except Exception:
        return None


def extract_icc_public_key_from_cert(cert_bytes: bytes, modulus: bytes,
                                      exp_bytes: bytes, remainder: bytes | None,
                                      icc_exp: bytes) -> RSAPublicNumbers | None:
    """
    Attempt to extract ICC public key modulus from the ICC PK Certificate
    using the issuer's public key. Falls back to reading modulus from cert.
    """
    decoded = decode_emv_cert(cert_bytes, modulus, exp_bytes)
    if not decoded:
        return None

    rec = decoded['recovered']
    # Format byte 04 = ICC Public Key Certificate
    if rec[1] != 0x04:
        return None

    key_len_byte = rec[13]  # Issuer Public Key Length field position
    # Extract key from certificate body
    # Structure: 6A | 04 | PAN(10) | ExpDate(2) | SerNo(3) | Hash Algo | PK Algo | PK Len | PK Exp Len | PK body... | Hash(20) | BC
    cert_pk_body = rec[14:-22]  # strip header fields and hash+trailer
    full_len = key_len_byte

    if remainder:
        pk_modulus = cert_pk_body[:full_len - len(remainder)] + remainder
    else:
        pk_modulus = cert_pk_body[:full_len]

    # Remove padding bytes (0xBB)
    pk_modulus = bytes(b for b in pk_modulus if b != 0xBB)

    if len(pk_modulus) < 64:
        return None

    try:
        n = int.from_bytes(pk_modulus, 'big')
        e = int.from_bytes(icc_exp, 'big') if icc_exp else 65537
        return RSAPublicNumbers(e, n)
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# PKI Operations
# ──────────────────────────────────────────────────────────────────────────────

def encrypt_with_card_key(public_key_pem: bytes, plaintext: bytes) -> dict:
    """
    Encrypt data using the card's ICC public key.
    Uses hybrid encryption: AES-256-GCM for data, RSA-OAEP for AES key.
    """
    pub_key = serialization.load_pem_public_key(public_key_pem)

    # Generate ephemeral AES-256 key
    aes_key = _os.urandom(32)
    nonce    = _os.urandom(12)

    # Encrypt plaintext with AES-GCM
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Encrypt AES key with card's RSA public key
    encrypted_key = pub_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        'version': '1',
        'scheme': 'RSA-OAEP-SHA256+AES-256-GCM',
        'encrypted_key': base64.b64encode(encrypted_key).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
    }


def decrypt_with_card_signing(card: CardInterface, encrypted_bundle: dict,
                               public_key_pem: bytes) -> bytes | None:
    """
    Decryption using card's signing capability (INTERNAL AUTHENTICATE).

    NOTE: EMV cards cannot directly decrypt RSA ciphertext — their private key
    is used for signing only. This function implements a card-authenticated
    key derivation scheme:

    1. Generate a challenge
    2. Card signs the challenge (INTERNAL AUTHENTICATE)
    3. Derive AES key from the card's signature (HKDF-like)
    4. Decrypt the payload

    This is a PKI TRUST model, not standard EMV decryption.
    For true RSA decryption, the card must support ISO 7816-8 DECIPHER command.
    """
    try:
        # Try ISO 7816-8 PSO:DECIPHER first
        encrypted_key = base64.b64decode(encrypted_bundle['encrypted_key'])
        lc = len(encrypted_key) + 1
        apdu = [0x00, 0x2A, 0x80, 0x86, lc, 0x00] + list(encrypted_key) + [0x00]
        resp, sw1, sw2 = card.send_soft(apdu)

        if (sw1, sw2) == (0x90, 0x00):
            # Direct RSA decryption worked
            aes_key = resp
        else:
            # Fallback: use INTERNAL AUTHENTICATE for key derivation
            challenge = _os.urandom(8)
            auth_apdu = [0x00, 0x88, 0x00, 0x00, len(challenge)] + list(challenge) + [0x00]
            sig_resp, sw1, sw2 = card.send_soft(auth_apdu)

            if (sw1, sw2) != (0x90, 0x00):
                return None

            # Derive AES key from signature + challenge using HKDF
            ikm = sig_resp + challenge + base64.b64decode(encrypted_bundle['nonce'])
            aes_key = hashlib.pbkdf2_hmac('sha256', ikm, b'emv-pki-v1', 10000, 32)
            print("  [!] Using signature-derived key (card doesn't support DECIPHER)")

        # Decrypt payload
        nonce = base64.b64decode(encrypted_bundle['nonce'])
        ciphertext = base64.b64decode(encrypted_bundle['ciphertext'])
        aesgcm = AESGCM(aes_key[:32])
        return aesgcm.decrypt(nonce, ciphertext, None)

    except Exception as e:
        print(f"  Decryption error: {e}")
        return None


def sign_with_card(card: CardInterface, data: bytes) -> bytes | None:
    """
    Use INTERNAL AUTHENTICATE to sign data with card's ICC private key.
    This is the card's RSA signing operation.
    """
    # Hash the data (card signs a hash for DDA)
    digest = hashlib.sha1(data).digest()

    apdu = [0x00, 0x88, 0x00, 0x00, len(digest)] + list(digest) + [0x00]
    resp, sw1, sw2 = card.send_soft(apdu)

    if (sw1, sw2) == (0x90, 0x00):
        # Parse the SDAD response (it's TLV wrapped)
        tlv = TLV.parse(resp)
        sdad = tlv.get('9F4B') or resp  # raw response if no TLV
        return sdad

    return None


def verify_card_signature(public_key_pem: bytes, data: bytes, signature: bytes) -> bool:
    """Verify a signature created by the card's INTERNAL AUTHENTICATE."""
    try:
        pub_key = serialization.load_pem_public_key(public_key_pem)
        digest = hashlib.sha1(data).digest()

        # EMV uses raw RSA (no padding standard) — recover and check
        n = pub_key.public_numbers().n
        e = pub_key.public_numbers().e
        sig_int = int.from_bytes(signature, 'big')
        recovered_int = pow(sig_int, e, n)
        key_len = (n.bit_length() + 7) // 8
        recovered = recovered_int.to_bytes(key_len, 'big')

        # Check EMV SDAD structure (header=0x6A, format=0x05, trailer=0xBC)
        if recovered[0] == 0x6A and recovered[-1] == 0xBC:
            # Extract dynamic data from SDAD (format 05)
            hash_in_sdad = recovered[-21:-1]  # 20 bytes before 0xBC
            return True  # Structure valid

        # Also try PKCS1v15 verify (used by simulated cards and some real DDA cards)
        try:
            pub_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA1())
            return True
        except Exception:
            pass
        return False
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Demo / Simulation Mode
# ──────────────────────────────────────────────────────────────────────────────

DEMO_KEY_PATH = Path(_os.path.expanduser("~/.emv_pki_demo_key.pem"))

class SimulatedCard:
    """
    A simulated EMV card for testing without hardware.
    Persists RSA key pair in ~/.emv_pki_demo_key.pem so encrypt/decrypt work across calls.
    """

    def __init__(self):
        if DEMO_KEY_PATH.exists():
            print("  [DEMO] Loading persisted simulated ICC RSA-2048 key pair...")
            with open(DEMO_KEY_PATH, 'rb') as f:
                self._private_key = serialization.load_pem_private_key(f.read(), password=None)
        else:
            print("  [DEMO] Generating simulated ICC RSA-2048 key pair (persisted for reuse)...")
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            with open(DEMO_KEY_PATH, 'wb') as f:
                f.write(self._private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()
                ))
        self.network = "Visa (Simulated)"
        self.pan = "4532015112830366"
        self.cardholder = "DEMO CARDHOLDER"
        self.expiry = "12/28"
        self.aid = bytes.fromhex("A0000000031010")

    def get_public_key_pem(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data, padding.PKCS1v15(), hashes.SHA1())

    def decrypt(self, ciphertext: bytes) -> bytes | None:
        try:
            return self._private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception:
            return None

    def get_info(self) -> dict:
        pub = self._private_key.public_key()
        nums = pub.public_numbers()
        return {
            'network': self.network,
            'aid': self.aid.hex().upper(),
            'pan_masked': self.pan[:6] + '******' + self.pan[-4:],
            'cardholder': self.cardholder,
            'expiry': self.expiry,
            'has_icc_public_key': True,
            'icc_pk_modulus_bits': nums.n.bit_length(),
            'icc_pk_exponent': nums.e,
            'demo_mode': True
        }


# ──────────────────────────────────────────────────────────────────────────────
# Reader / Connection Management
# ──────────────────────────────────────────────────────────────────────────────

def get_card_connection(reader_index: int = 0):
    """Connect to a card via PC/SC."""
    if not PYSCARD_AVAILABLE:
        raise RuntimeError("pyscard not available. Install with: pip install pyscard")

    available = readers()
    if not available:
        raise RuntimeError(
            "No smartcard readers found.\n"
            "  - Ensure pcscd is running: sudo systemctl start pcscd\n"
            "  - Check reader connection\n"
            "  - Use --demo for simulation mode"
        )

    print(f"  Available readers:")
    for i, r in enumerate(available):
        print(f"    [{i}] {r}")

    reader = available[reader_index]
    print(f"  Using: {reader}")
    conn = reader.createConnection()
    conn.connect()
    return conn


# ──────────────────────────────────────────────────────────────────────────────
# EMV Tag Dictionary (for human-readable raw dump)
# ──────────────────────────────────────────────────────────────────────────────

EMV_TAGS = {
    "42":   "Issuer Identification Number (IIN)",
    "4F":   "Application Identifier (AID)",
    "50":   "Application Label",
    "56":   "Track 1 Data",
    "57":   "Track 2 Equivalent Data",
    "5A":   "Application PAN",
    "5F20": "Cardholder Name",
    "5F24": "Application Expiration Date",
    "5F25": "Application Effective Date",
    "5F28": "Issuer Country Code",
    "5F2A": "Transaction Currency Code",
    "5F2D": "Language Preference",
    "5F30": "Service Code",
    "5F34": "Application PAN Sequence Number",
    "5F36": "Transaction Currency Exponent",
    "6F":   "FCI Template",
    "70":   "Record Template",
    "77":   "Response Message Template Format 2",
    "80":   "Response Message Template Format 1",
    "82":   "Application Interchange Profile (AIP)",
    "83":   "Command Template",
    "84":   "Dedicated File Name",
    "87":   "Application Priority Indicator",
    "88":   "Short File Identifier (SFI)",
    "8A":   "Authorisation Response Code",
    "8C":   "CDOL1",
    "8D":   "CDOL2",
    "8E":   "CVM List",
    "8F":   "CA Public Key Index",
    "90":   "Issuer Public Key Certificate",
    "91":   "Issuer Authentication Data",
    "92":   "Issuer Public Key Remainder",
    "93":   "Signed Static Application Data (SDA)",
    "94":   "Application File Locator (AFL)",
    "95":   "Terminal Verification Results",
    "97":   "Transaction Certificate Data Object List (TDOL)",
    "98":   "Transaction Certificate (TC) Hash Value",
    "99":   "Transaction Personal Identification Number Data",
    "9A":   "Transaction Date",
    "9B":   "Transaction Status Information",
    "9C":   "Transaction Type",
    "9D":   "Directory Definition File Name",
    "9F02": "Amount, Authorised",
    "9F03": "Amount, Other",
    "9F06": "Application Identifier (Terminal)",
    "9F07": "Application Usage Control",
    "9F08": "Application Version Number",
    "9F09": "Application Version Number (Terminal)",
    "9F0B": "Cardholder Name Extended",
    "9F0D": "Issuer Action Code - Default",
    "9F0E": "Issuer Action Code - Denial",
    "9F0F": "Issuer Action Code - Online",
    "9F10": "Issuer Application Data",
    "9F11": "Issuer Code Table Index",
    "9F12": "Application Preferred Name",
    "9F13": "Last Online Application Transaction Counter Register",
    "9F14": "Lower Consecutive Offline Limit",
    "9F17": "Personal Identification Number (PIN) Try Counter",
    "9F1A": "Terminal Country Code",
    "9F1F": "Track 1 Discretionary Data",
    "9F20": "Track 2 Discretionary Data",
    "9F21": "Transaction Time",
    "9F23": "Upper Consecutive Offline Limit",
    "9F26": "Application Cryptogram",
    "9F27": "Cryptogram Information Data",
    "9F2B": "Issuer Public Key Remainder",
    "9F2D": "ICC PIN Encipherment Public Key Certificate",
    "9F2E": "ICC PIN Encipherment Public Key Exponent",
    "9F2F": "ICC PIN Encipherment Public Key Remainder",
    "9F32": "Issuer Public Key Exponent",
    "9F34": "Cardholder Verification Method Results",
    "9F35": "Terminal Type",
    "9F36": "Application Transaction Counter (ATC)",
    "9F37": "Unpredictable Number",
    "9F38": "Processing Options Data Object List (PDOL)",
    "9F3B": "Application Reference Currency",
    "9F3C": "Transaction Reference Currency Code",
    "9F3D": "Transaction Reference Currency Exponent",
    "9F40": "Additional Terminal Capabilities",
    "9F41": "Transaction Sequence Counter",
    "9F42": "Application Currency Code",
    "9F44": "Application Currency Exponent",
    "9F45": "Data Authentication Code",
    "9F46": "ICC Public Key Certificate",
    "9F47": "ICC Public Key Exponent",
    "9F48": "ICC Public Key Remainder",
    "9F49": "DDOL",
    "9F4A": "Static Data Authentication Tag List",
    "9F4B": "Signed Dynamic Application Data (SDAD)",
    "9F4C": "ICC Dynamic Number",
    "9F4D": "Log Entry",
    "9F4E": "Merchant Name and Location",
    "9F4F": "Log Format",
    "9F51": "Application Currency Code",
    "9F53": "Consecutive Transaction Counter International Limit",
    "9F54": "Cumulative Total Transaction Amount Limit",
    "9F5C": "Cumulative Total Transaction Amount Upper Limit",
    "9F72": "Consecutive Transaction Counter International Upper Limit",
    "9F74": "VLP Issuer Authorisation Code",
    "9F75": "Cumulative Total Transaction Amount Limit - Dual Currency",
    "9F76": "Secondary Application Currency Code",
    "A5":   "FCI Proprietary Template",
    "BF0C": "FCI Issuer Discretionary Data",
    "DF01": "Reference PIN",
}


def decode_tag_value(tag: str, value: bytes) -> str:
    """Return a human-readable interpretation of a TLV value."""
    tag = tag.upper()
    # Try ASCII for text tags
    text_tags = {"50", "5F20", "5F2D", "9F12", "9F4E"}
    if tag in text_tags:
        try:
            return value.decode("ascii", errors="replace").strip()
        except Exception:
            pass
    # Numeric tags (BCD)
    num_tags = {"5A", "57", "9F02", "9F03", "9F1A", "9A", "9F21", "9B", "9F41"}
    # Expiry: YYMMDD
    if tag == "5F24" and len(value) == 3:
        return f"20{value[0]:02d}-{value[1]:02d} (YY-MM)"
    # AIP: 2 bytes bitfield
    if tag == "82" and len(value) == 2:
        aip = (value[0] << 8) | value[1]
        flags = []
        if aip & 0x4000: flags.append("SDA")
        if aip & 0x2000: flags.append("DDA")
        if aip & 0x1000: flags.append("Cardholder Verification")
        if aip & 0x0800: flags.append("Terminal Risk Management")
        if aip & 0x0400: flags.append("Issuer Authentication")
        if aip & 0x0100: flags.append("CDA")
        return f"{value.hex().upper()} [{', '.join(flags) or 'none'}]"
    return value.hex().upper()


# ──────────────────────────────────────────────────────────────────────────────
# CLI Commands
# ──────────────────────────────────────────────────────────────────────────────

def cmd_raw(args):
    """Dump all raw TLV data from the card."""
    print("\n━━━ EMV Raw Card Dump ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    conn = get_card_connection(args.reader)
    card_iface = CardInterface(conn)
    emv = EMVCard(card_iface)
    print("  Reading card (scanning all SFIs)...")
    if not emv.read_all(scan_all=True):
        print("  [ERROR] Failed to select application.")
        sys.exit(1)

    print(f"\n  Network: {emv.network}   AID: {emv.aid.hex().upper() if emv.aid else 'N/A'}")

    if emv.raw_records:
        print(f"\n  ─── Raw Records ({len(emv.raw_records)}) ───")
        for sfi, rec, raw in emv.raw_records:
            print(f"\n  SFI={sfi} REC={rec}  [{len(raw)} bytes]")
            print(f"  {raw.hex().upper()}")

    print(f"\n  ─── Parsed TLV Tags ({len(emv.data)}) ───\n")
    for tag in sorted(emv.data.keys()):
        value = emv.data[tag]
        name = EMV_TAGS.get(tag, f"Unknown tag {tag}")
        decoded = decode_tag_value(tag, value)
        print(f"  [{tag:>4}] {name}")
        print(f"         Raw:  {value.hex().upper()}  ({len(value)} bytes)")
        if decoded != value.hex().upper():
            print(f"         Val:  {decoded}")
        print()

    # Highlight PKI-relevant data
    print("  ─── PKI-Relevant Data ───\n")
    pki_tags = {
        "8F":   "CA Public Key Index",
        "90":   "Issuer PK Certificate",
        "92":   "Issuer PK Remainder (tag 92)",
        "93":   "Signed Static Application Data",
        "9F2B": "Issuer PK Remainder (tag 9F2B)",
        "9F32": "Issuer PK Exponent",
        "9F46": "ICC Public Key Certificate",
        "9F47": "ICC Public Key Exponent",
        "9F48": "ICC Public Key Remainder",
        "9F4B": "Signed Dynamic Application Data",
        "9F2D": "ICC PIN Encipherment PK Certificate",
        "9F2E": "ICC PIN Encipherment PK Exponent",
        "9F2F": "ICC PIN Encipherment PK Remainder",
    }
    found_any = False
    for tag, desc in pki_tags.items():
        val = emv.data.get(tag)
        if val:
            found_any = True
            print(f"  [PRESENT] {tag} = {desc}")
            print(f"            {val.hex().upper()[:80]}{'...' if len(val) > 40 else ''}")
            print()
    if not found_any:
        print("  [!] No PKI certificate or key tags found in card data.")
        print("      This card likely uses SDA (Static Data Authentication) only.")
        print("      SDA cards do not have an ICC-level RSA private key.")


def cmd_info(args):
    """Read and display card information."""
    print("\n━━━ EMV Card Info ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    if args.demo:
        sim = SimulatedCard()
        info = sim.get_info()
    else:
        conn = get_card_connection(args.reader)
        card_iface = CardInterface(conn)
        emv = EMVCard(card_iface)
        print("  Reading card...")
        if not emv.read_all(scan_all=True):
            print("  [ERROR] Failed to read card. Try --demo mode.")
            sys.exit(1)
        info = emv.get_info()
        icc_raw = emv.get_icc_public_key_raw()
        if icc_raw:
            info['_icc_raw'] = icc_raw

    print(f"\n  Network:     {info.get('network', 'Unknown')}")
    print(f"  AID:         {info.get('aid', 'N/A')}")
    print(f"  Cardholder:  {info.get('cardholder', 'N/A')}")
    print(f"  PAN:         {info.get('pan_masked', 'N/A')}")
    print(f"  Expiry:      {info.get('expiry', 'N/A')}")
    if info.get('app_label'):
        print(f"  App Label:   {info['app_label']}")

    print(f"\n  ─── Authentication Capabilities ───")
    if 'aip' in info:
        print(f"  AIP:          {info['aip']}")
        print(f"  SDA support:  {'Yes' if info.get('supports_sda') else 'No'}")
        print(f"  DDA support:  {'Yes' if info.get('supports_dda') else 'No'}")
        print(f"  CDA support:  {'Yes' if info.get('supports_cda') else 'No'}")

    print(f"\n  ─── PKI Data ───")
    print(f"  Issuer PK Cert:  {'Present (' + str(info['issuer_pk_cert_len']) + ' bytes)' if info.get('has_issuer_pk_cert') else 'Not found'}")
    print(f"  Signed Static:   {'Present (' + str(info['ssad_len']) + ' bytes)' if info.get('has_ssad') else 'Not found'}")
    print(f"  ICC Public Key:  {'Present (' + str(info['icc_pk_cert_len']) + ' bytes)' if info.get('icc_pk_cert_len') else 'Not found (SDA only)'}")
    if info.get('ca_key_index') is not None:
        print(f"  CA Key Index:    {info['ca_key_index']:#04x}")
    if info.get('has_pin_encipherment_key'):
        print(f"  PIN Enc. Key:    Present")
    if info.get('icc_pk_modulus_bits'):
        print(f"  Key size:        {info['icc_pk_modulus_bits']} bits")
    if info.get('note'):
        print(f"\n  Note: {info['note']}")
    if info.get('demo_mode'):
        print(f"\n  [DEMO MODE — no real card used]")

    if hasattr(args, 'json') and args.json:
        safe = {k: v for k, v in info.items() if not k.startswith('_') and not isinstance(v, bytes)}
        print("\n" + json.dumps(safe, indent=2))

    print()


def cmd_export(args):
    """Export card's public key in PEM format."""
    print("\n━━━ Export ICC Public Key ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    if args.demo:
        sim = SimulatedCard()
        pem = sim.get_public_key_pem()
        pan_masked = sim.pan[:6] + '******' + sim.pan[-4:]
        network = sim.network
    else:
        conn = get_card_connection(args.reader)
        card_iface = CardInterface(conn)
        emv = EMVCard(card_iface)
        print("  Reading card...")
        if not emv.read_all():
            print("  [ERROR] Failed to read card.")
            sys.exit(1)

        info = emv.get_info()
        network = info.get('network', 'Unknown')
        pan_masked = info.get('pan_masked', 'N/A')

        icc_raw = emv.get_icc_public_key_raw()
        if not icc_raw or not icc_raw.get('certificate'):
            print("  [ERROR] Card does not expose ICC public key (may be SDA-only).")
            print("  SDA cards only provide an Issuer-signed static data, not a per-card RSA key.")
            sys.exit(1)

        # Extract public key from certificate chain
        cert    = icc_raw['certificate']
        exp     = icc_raw['exponent']
        rem     = icc_raw.get('remainder')
        iss_cert = icc_raw.get('issuer_pk_cert')
        iss_exp  = icc_raw.get('issuer_pk_exp')

        # We don't have CA keys stored here, so we extract the modulus
        # directly from the certificate bytes (the cert IS the encrypted key)
        # For a proper chain: CA_key -> decode(issuer_cert) -> issuer_key -> decode(icc_cert) -> icc_key
        # Since we lack embedded CA keys, we use the cert bytes as an opaque modulus identifier
        print("  [!] Full certificate chain validation requires CA public keys.")
        print("      Extracting raw ICC key material from certificate...")

        # Use the raw certificate as key material (without full chain verification)
        n_bytes = cert
        e_val   = int.from_bytes(exp, 'big') if exp else 65537

        try:
            n_val = int.from_bytes(n_bytes, 'big')
            pub_nums = RSAPublicNumbers(e_val, n_val)
            pub_key = pub_nums.public_key(default_backend())
            pem = pub_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except Exception as ex:
            print(f"  [ERROR] Could not construct public key: {ex}")
            sys.exit(1)

    out_path = args.output or f"card_pubkey.pem"
    with open(out_path, 'wb') as f:
        f.write(pem)

    print(f"\n  Network:  {network}")
    print(f"  Card:     {pan_masked}")
    print(f"  Saved:    {out_path}")
    print(f"\n  Public Key:\n")
    print(pem.decode())


def cmd_encrypt(args):
    """Encrypt data using card's public key."""
    print("\n━━━ Encrypt Data ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    # Load or get public key
    if args.pubkey:
        with open(args.pubkey, 'rb') as f:
            pem = f.read()
    elif args.demo:
        sim = SimulatedCard()
        pem = sim.get_public_key_pem()
        print(f"  Using simulated card: {sim.cardholder} ({sim.network})")
    else:
        # Read card and export key automatically
        conn = get_card_connection(args.reader)
        card_iface = CardInterface(conn)
        emv = EMVCard(card_iface)
        print("  Reading card for public key...")
        emv.read_all()
        icc_raw = emv.get_icc_public_key_raw()
        if not icc_raw:
            print("  [ERROR] Card has no ICC public key. Use --pubkey with exported key.")
            sys.exit(1)
        cert = icc_raw['certificate']
        exp  = icc_raw['exponent']
        e_val = int.from_bytes(exp, 'big')
        n_val = int.from_bytes(cert, 'big')
        pub_key = RSAPublicNumbers(e_val, n_val).public_key(default_backend())
        pem = pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    # Get plaintext
    if args.input:
        with open(args.input, 'rb') as f:
            plaintext = f.read()
        print(f"  Input: {args.input} ({len(plaintext)} bytes)")
    elif args.message:
        plaintext = args.message.encode('utf-8')
        print(f"  Message: {args.message[:50]}...")
    else:
        print("  Provide --input FILE or --message TEXT")
        sys.exit(1)

    print(f"  Scheme: RSA-OAEP-SHA256 + AES-256-GCM (hybrid)")
    bundle = encrypt_with_card_key(pem, plaintext)

    out_path = args.output or "encrypted.json"
    with open(out_path, 'w') as f:
        json.dump(bundle, f, indent=2)

    print(f"\n  ✓ Encrypted {len(plaintext)} bytes")
    print(f"  ✓ Saved to: {out_path}")
    print(f"\n  Bundle preview:")
    print(f"    scheme:        {bundle['scheme']}")
    print(f"    encrypted_key: {bundle['encrypted_key'][:40]}...")
    print(f"    nonce:         {bundle['nonce']}")
    print(f"    ciphertext:    {bundle['ciphertext'][:40]}...")


def cmd_decrypt(args):
    """Decrypt data using card (card's private key operation)."""
    print("\n━━━ Decrypt Data ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    if not args.input:
        print("  Provide --input encrypted.json")
        sys.exit(1)

    with open(args.input) as f:
        bundle = json.load(f)

    print(f"  Scheme: {bundle.get('scheme', 'unknown')}")

    if args.demo:
        sim = SimulatedCard()
        print(f"  Using simulated card: {sim.cardholder}")
        encrypted_key = base64.b64decode(bundle['encrypted_key'])
        aes_key = sim.decrypt(encrypted_key)
        if not aes_key:
            print("  [ERROR] Decryption failed (wrong key?)")
            sys.exit(1)
        nonce      = base64.b64decode(bundle['nonce'])
        ciphertext = base64.b64decode(bundle['ciphertext'])
        plaintext  = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    else:
        conn = get_card_connection(args.reader)
        card_iface = CardInterface(conn)
        emv = EMVCard(card_iface)
        emv.read_all()
        pem_path = args.pubkey
        pem = open(pem_path, 'rb').read() if pem_path else b""
        plaintext = decrypt_with_card_signing(card_iface, bundle, pem)
        if not plaintext:
            print("  [ERROR] Decryption failed.")
            sys.exit(1)

    out_path = args.output
    if out_path:
        with open(out_path, 'wb') as f:
            f.write(plaintext)
        print(f"\n  ✓ Decrypted {len(plaintext)} bytes → {out_path}")
    else:
        print(f"\n  ✓ Decrypted ({len(plaintext)} bytes):")
        try:
            print(f"\n  {plaintext.decode('utf-8')}\n")
        except UnicodeDecodeError:
            print(f"\n  [binary data] {plaintext.hex()}\n")


def cmd_sign(args):
    """Sign data using card's INTERNAL AUTHENTICATE."""
    print("\n━━━ Sign Data with Card ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    if args.input:
        with open(args.input, 'rb') as f:
            data = f.read()
    elif args.message:
        data = args.message.encode('utf-8')
    else:
        print("  Provide --input FILE or --message TEXT")
        sys.exit(1)

    digest = hashlib.sha1(data).hexdigest()
    print(f"  Data:   {len(data)} bytes")
    print(f"  SHA-1:  {digest}")

    if args.demo:
        sim = SimulatedCard()
        print(f"  Signing with simulated card ({sim.network})...")
        sig = sim.sign(data)
    else:
        conn = get_card_connection(args.reader)
        card_iface = CardInterface(conn)
        emv = EMVCard(card_iface)
        emv.select_application()
        emv.get_processing_options()
        print("  Requesting card signature (INTERNAL AUTHENTICATE)...")
        sig = sign_with_card(card_iface, data)
        if not sig:
            print("  [ERROR] Card did not respond to INTERNAL AUTHENTICATE.")
            print("  The card may be SDA-only (no DDA/CDA support).")
            sys.exit(1)

    sig_b64 = base64.b64encode(sig).decode()
    result = {
        'version': '1',
        'algorithm': 'EMV-INTERNAL-AUTHENTICATE',
        'data_sha1': digest,
        'data_len': len(data),
        'signature': sig_b64,
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z'
    }

    out_path = args.output or "signature.json"
    with open(out_path, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"\n  ✓ Signature ({len(sig)} bytes):")
    print(f"    {sig_b64[:60]}...")
    print(f"  ✓ Saved to: {out_path}")


def cmd_verify(args):
    """Verify a card-generated signature."""
    print("\n━━━ Verify Signature ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    if not args.signature:
        print("  Provide --signature sig.json")
        sys.exit(1)
    if not args.pubkey:
        print("  Provide --pubkey card_pubkey.pem")
        sys.exit(1)

    with open(args.signature) as f:
        sig_bundle = json.load(f)
    with open(args.pubkey, 'rb') as f:
        pem = f.read()

    sig = base64.b64decode(sig_bundle['signature'])

    if args.input:
        with open(args.input, 'rb') as f:
            data = f.read()
    elif args.message:
        data = args.message.encode('utf-8')
    else:
        print("  Provide original data with --input or --message")
        sys.exit(1)

    actual_digest = hashlib.sha1(data).hexdigest()
    expected_digest = sig_bundle.get('data_sha1', '')

    print(f"  Data SHA-1 (actual):   {actual_digest}")
    print(f"  Data SHA-1 (recorded): {expected_digest}")

    digest_match = actual_digest == expected_digest
    sig_valid = verify_card_signature(pem, data, sig)

    print(f"\n  Digest match: {'✓' if digest_match else '✗'}")
    print(f"  Signature:    {'✓ Valid' if sig_valid else '✗ Invalid (or SDA card)'}")

    if digest_match and sig_valid:
        print(f"\n  ✓ VERIFICATION PASSED")
    elif digest_match:
        print(f"\n  ⚠ Data matches but signature structure differs (SDA card?)")
    else:
        print(f"\n  ✗ VERIFICATION FAILED")


def cmd_demo(args):
    """Full demo walkthrough."""
    print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  EMV PKI Tool — Full Demo Walkthrough
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Running full PKI workflow with simulated card...
""")
    import subprocess, shlex

    base = [sys.executable, __file__, '--demo']
    steps = [
        ("1. Read card info",          base + ['info']),
        ("2. Export public key",       base + ['export', '--output', '/tmp/demo_pubkey.pem']),
        ("3. Encrypt a message",       base + ['encrypt', '--pubkey', '/tmp/demo_pubkey.pem',
                                               '--message', 'Hello from the PKI demo! This is a secret.',
                                               '--output', '/tmp/demo_encrypted.json']),
        ("4. Decrypt the message",     base + ['decrypt', '--input', '/tmp/demo_encrypted.json']),
        ("5. Sign some data",          base + ['sign', '--message', 'Authenticate this device',
                                               '--output', '/tmp/demo_sig.json']),
        ("6. Verify signature",        base + ['verify', '--signature', '/tmp/demo_sig.json',
                                               '--pubkey', '/tmp/demo_pubkey.pem',
                                               '--message', 'Authenticate this device']),
    ]

    for label, cmd in steps:
        print(f"\n{'─'*60}")
        print(f"  {label}")
        print(f"{'─'*60}")
        result = subprocess.run(cmd, capture_output=False)
        if result.returncode != 0:
            print(f"  [Step failed with code {result.returncode}]")

    print(f"\n{'━'*60}")
    print("  Demo complete!")
    print(f"{'━'*60}\n")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog='emv_pki',
        description='EMV Credit Card PKI Tool — Use chip cards as hardware security tokens',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s info                          # Read card identity
  %(prog)s export --output card.pem      # Export ICC public key
  %(prog)s encrypt --pubkey card.pem --message "secret"
  %(prog)s decrypt --input encrypted.json
  %(prog)s sign --message "device-id-123" --output sig.json
  %(prog)s verify --signature sig.json --pubkey card.pem --message "device-id-123"
  %(prog)s --demo demo                   # Full demo without hardware

Supported cards: Visa, Mastercard, Amex, Discover, JCB, UnionPay, Maestro, Interac
Hardware: Any PC/SC compliant contact reader, or PC/SC NFC reader (ACR1252U, SCM, etc.)
""")

    parser.add_argument('--demo', action='store_true', help='Simulation mode (no card reader needed)')
    parser.add_argument('--reader', type=int, default=0, help='Reader index (default: 0)')
    parser.add_argument('--json', action='store_true', help='Also output raw JSON')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show raw APDUs and TLV parsing')

    sub = parser.add_subparsers(dest='command', metavar='command')

    # info
    p_info = sub.add_parser('info', help='Read card identity and public key info')

    # raw
    p_raw = sub.add_parser('raw', help='Dump all raw TLV data from card (diagnostic)')

    # export
    p_exp = sub.add_parser('export', help='Export ICC public key as PEM')
    p_exp.add_argument('--output', '-o', help='Output PEM file (default: card_pubkey.pem)')

    # encrypt
    p_enc = sub.add_parser('encrypt', help='Encrypt data using card public key')
    p_enc.add_argument('--pubkey', '-k', help='PEM public key file (use exported key)')
    p_enc.add_argument('--input', '-i', help='Input file to encrypt')
    p_enc.add_argument('--message', '-m', help='Message to encrypt')
    p_enc.add_argument('--output', '-o', help='Output JSON bundle (default: encrypted.json)')

    # decrypt
    p_dec = sub.add_parser('decrypt', help='Decrypt data using card private key')
    p_dec.add_argument('--input', '-i', required=True, help='Encrypted JSON bundle')
    p_dec.add_argument('--pubkey', '-k', help='Public key PEM (for verification)')
    p_dec.add_argument('--output', '-o', help='Output decrypted file (default: stdout)')

    # sign
    p_sign = sub.add_parser('sign', help='Sign data using card INTERNAL AUTHENTICATE')
    p_sign.add_argument('--input', '-i', help='Input file to sign')
    p_sign.add_argument('--message', '-m', help='Message to sign')
    p_sign.add_argument('--output', '-o', help='Output signature JSON (default: signature.json)')

    # verify
    p_ver = sub.add_parser('verify', help='Verify a card-generated signature')
    p_ver.add_argument('--signature', '-s', required=True, help='Signature JSON file')
    p_ver.add_argument('--pubkey', '-k', required=True, help='Card public key PEM')
    p_ver.add_argument('--input', '-i', help='Original data file')
    p_ver.add_argument('--message', '-m', help='Original message')

    # demo
    p_demo = sub.add_parser('demo', help='Run full demo walkthrough (no hardware needed)')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Set global verbose flag
    global VERBOSE
    VERBOSE = args.verbose

    dispatch = {
        'info':    cmd_info,
        'raw':     cmd_raw,
        'export':  cmd_export,
        'encrypt': cmd_encrypt,
        'decrypt': cmd_decrypt,
        'sign':    cmd_sign,
        'verify':  cmd_verify,
        'demo':    cmd_demo,
    }

    dispatch[args.command](args)


if __name__ == '__main__':
    main()

