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
All operations require a real card in the reader — no simulation mode.

Supports: Visa, Mastercard, Amex, Discover, JCB, UnionPay, Maestro, Interac

Requirements:
  - A PC/SC compliant smart card reader (contact) OR an NFC reader
  - Linux with pcscd running: sudo systemctl start pcscd
  - pip install pyscard cryptography

Commands:
  info      - Read card identity and public key
  raw       - Dump all raw TLV tags (diagnostic)
  export    - Export card's ICC public key in PEM format
  probe     - Exhaustive crypto APDU capability test (with full EMV context)
  encrypt   - Encrypt data to the card's ICC public key (RSA-OAEP hybrid)
  decrypt   - Decrypt using card's PSO:DECIPHER command
  sign      - Use card to sign data via INTERNAL AUTHENTICATE (DDA)
  verify    - Verify a card-generated SDAD signature
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

# ──────────────────────────────────────────────────────────────────────────────
# Smartcard library (required — no simulation mode)
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

# ──────────────────────────────────────────────────────────────────────────────
# EMV Certification Authority (CA) Public Keys
# Sourced from publicly available open-source EMV implementations:
#   - https://github.com/merlokk/PCSCEMV/blob/master/ca-public-keys.txt
#   - https://github.com/lumag/emv-tools/tree/master/data
#   - https://www.eftlab.com/knowledge-base/list-of-ca-public-keys
#
# Format: { RID_hex: { key_index_hex: (modulus_hex, exponent_hex) } }
# Exponent 03 = 0x03 (3), 010001 = 0x10001 (65537)
#
# Key sizes: 768-bit = 96 bytes, 896-bit = 112 bytes, 1024-bit = 128 bytes,
#            1152-bit = 144 bytes, 1408-bit = 176 bytes, 1536-bit = 192 bytes,
#            1792-bit = 224 bytes, 1984-bit = 248 bytes, 2048-bit = 256 bytes
# ──────────────────────────────────────────────────────────────────────────────
EMV_CA_KEYS = {
    # ── Visa (RID A000000003) ─────────────────────────────────────────────────
    "A000000003": {
        # Index 01 — 1024-bit, exp 3, expired 2009-12-31
        "01": (
            "C696034213D7D8546984579D1D0F0EA519CFF8DEFFC429354CF3A871A6F7183F"
            "1228DA5C7470C055387100CB935A712C4E2864DF5D64BA93FE7E63E71F25B1E5"
            "F5298575EBE1C63AA617706917911DC2A75AC28B251C7EF40F2365912490B939"
            "BCA2124A30A28F54402C34AECA331AB67E1E79B285DD5771B5D9FF79EA630B75",
            "03",
        ),
        # Index 03 — 896-bit, exp 3
        "03": (
            "B3E5E667506C47CAAFB12A2633819350846697DD65A796E5CE77C57C626A66F7"
            "0BB630911612AD2832909B8062291BECA46CD33B66A6F9C9D48CED8B4FC8561C"
            "8A1D8FB15862C9EB60178DEA2BE1F82236FFCFF4F3843C272179DCDD384D5410"
            "53DA6A6A0D3CE48FDC2DC4E3E0EEE15F",
            "03",
        ),
        # Index 05 — 768-bit, exp 3
        "05": (
            "D0135CE8A4436C7F9D5CC66547E30EA402F98105B71722E24BC08DCC80AB7E71"
            "EC23B8CE6A1DC6AC2A8CF55543D74A8AE7B388F9B174B7F0D756C22CBB5974F"
            "9016A56B601CCA64C71F04B78E86C501B193A5556D5389ECE4DEA258AB97F52A3",
            "03",
        ),
        # Index 06 — 768-bit, exp 3
        "06": (
            "F934FC032BE59B609A9A649E04446F1B365D1D23A1E6574E490170527EDF32F3"
            "98326159B39B63D07E95E6276D7FCBB786925182BC0667FBD8F6566B361CA41A"
            "38DDF227091B87FA4F47BAC780AC47E15A6A0FB65393EB3473E8D193A07EB579",
            "03",
        ),
        # Index 07 — 1152-bit, exp 3, expired 2017-12-31
        "07": (
            "A89F25A56FA6DA258C8CA8B40427D927B4A1EB4D7EA326BBB12F97DED70AE5E4"
            "480FC9C5E8A972177110A1CC318D06D2F8F5C4844AC5FA79A4DC470BB11ED635"
            "699C17081B90F1B984F12E92C1C529276D8AF8EC7F28492097D8CD5BECEA16FE"
            "4088F6CFAB4A1B42328A1B996F9278B0B7E3311CA5EF856C2F888474B83612A8"
            "2E4E00D0CD4069A6783140433D50725F",
            "03",
        ),
        # Index 08 — 1408-bit, exp 3, expired 2022-12-31
        "08": (
            "D9FD6ED75D51D0E30664BD157023EAA1FFA871E4DA65672B863D255E81E137A5"
            "1DE4F72BCC9E44ACE12127F87E263D3AF9DD9CF35CA4A7B01E907000BA85D249"
            "54C2FCA3074825DDD4C0C8F186CB020F683E02F2DEAD3969133F06F7845166AC"
            "EB57CA0FC2603445469811D293BFEFBAFAB57631B3DD91E796BF850A25012F1A"
            "E38F05AA5C4D6D03B1DC2E568612785938BBC9B3CD3A910C1DA55A5A9218ACE0"
            "F7A21287752682F15832A678D6E1ED0B",
            "03",
        ),
        # Index 09 — 1984-bit, exp 3, expires 2028-12-31  (you already had this)
        "09": (
            "9D912248DE0A4E39C1A7DDE3F6D2588992C1A4095AFBD1824D1BA74847F2BC49"
            "26D2EFD904B4B54954CD189A54C5D1179654F8F9B0D2AB5F0357EB642FEDA95D"
            "3912C6576945FAB897E7062CAA44A4AA06B8FE6E3DBA18AF6AE3738E30429EE9"
            "BE03427C9D64F695FA8CAB4BFE376853EA34AD1D76BFCAD15908C077FFE6DC55"
            "21ECEF5D278A96E26F57359FFAEDA19434B937F1AD999DC5C41EB11935B44C18"
            "100E857F431A4A5A6BB65114F174C2D7B59FDF237D6BB1DD0916E644D709DED5"
            "6481477C75D95CDD68254615F7740EC07F330AC5D67BCD75BF23D28A140826C0"
            "26DBDE971A37CD3EF9B8DF644AC385010501EFC6509D7A41",
            "03",
        ),
        # Index 10 — 1024-bit, exp 3
        "10": (
            "9F2701C0909CCBD8C3ED3E071C69F776160022FF3299807ED7A035ED5752770E"
            "232D56CC3BE159BD8F0CA8B59435688922F406F55C75639457BBABEFE9A86B22"
            "69EF223E34B91AA6DF2CCAD03B4AD4B443D61575CA960845E6C69040101E231D"
            "9EF811AD99B0715065A0E661449C41B4B023B7716D1E4AFF1C90704E55AE1225",
            "03",
        ),
        # Index 20 — 1024-bit, exp 3
        "20": (
            "998D2AD946A60FC597D93807DB54B2B0A550871E43F1779F073AF08D9B04ABD1"
            "7C8A7DAA3E66EE443F30F92648FC53DA57A78364B062FEDB50F7235B937E16E5"
            "F6D9E6BA8F106FB325ECA25125111CE04B43098CDEA8A41426FC6D94F8A47619"
            "EDB12789581808692CFBA1F38E8008CC5E02066A1889D52F77B9A121E6597F39",
            "03",
        ),
        # Index 50 — 1024-bit, exp 65537
        "50": (
            "D11197590057B84196C2F4D11A8F3C05408F422A35D702F90106EA5B019BB28A"
            "E607AA9CDEBCD0D81A38D48C7EBB0062D287369EC0C42124246AC30D80CD602A"
            "B7238D51084DED4698162C59D25EAC1E66255B4DB2352526EF0982C3B8AD3D1C"
            "CE85B01DB5788E75E09F44BE7361366DEF9D1E1317B05E5D0FF5290F88A0DB47",
            "010001",
        ),
        # Index 51 — 768-bit, exp 3
        "51": (
            "BBE43877CC28C0CE1E14BC14E8477317E218364531D155BB8AC5B63C0D6E284D"
            "D24259193899F9C04C30BAF167D57929451F67AEBD3BBD0D41444501847D8F02"
            "F2C2A2D14817D97AE2625DC163BF8B484C40FFB51749CEDDE9434FB2A0A41099",
            "03",
        ),
        # Index 52 — 1024-bit, exp 65537
        "52": (
            "B831414E0B4613922BD35B4B36802BC1E1E81C95A27C958F5382003DF646154C"
            "A92FC1CE02C3BE047A45E9B02A9089B4B90278237C965192A0FCC86BB49BC82A"
            "E6FDC2DE709006B86C7676EFDF597626FAD633A4F7DC48C445D37EB55FCB3B1A"
            "BB95BAAA826D5390E15FD14ED403FA2D0CB841C650609524EC555E3BC56CA957",
            "010001",
        ),
        # Index 58 — 1600-bit, exp 65537 (test key)
        "58": (
            "99552C4A1ECD68A0260157FC4151B5992837445D3FC57365CA5692C87BE358CD"
            "CDF2C92FB6837522842A48EB11CDFFE2FD91770C7221E4AF6207C2DE4004C7DE"
            "E1B6276DC62D52A87D2CD01FBF2DC4065DB52824D2A2167A06D19E6A0F781071"
            "CDB2DD314CB94441D8DC0E936317B77BF06F5177F6C5ABA3A3BC6AA30209C972"
            "60B7A1AD3A192C9B8CD1D153570AFCC87C3CD681D13E997FE33B3963A0A1C797"
            "72ACF991033E1B8397AD0341500E48A24770BC4CBE19D2CCF419504FDBF0389B"
            "C2F2FDCD4D44E61F",
            "010001",
        ),
        # Index 90 — 512-bit, exp 3 (legacy/short)
        "90": (
            "C26B3CB3833E42D8270DC10C8999B2DA18106838650DA0DBF154EFD51100AD14"
            "4741B2A87D6881F8630E3348DEA3F78038E9B21A697EB2A6716D32CBF26086F1",
            "03",
        ),
        # Index 92 — 1408-bit, exp 3 (test key)
        "92": (
            "996AF56F569187D09293C14810450ED8EE3357397B18A2458EFAA92DA3B6DF65"
            "14EC060195318FD43BE9B8F0CC669E3F844057CBDDF8BDA191BB64473BC8DC9A"
            "730DB8F6B4EDE3924186FFD9B8C7735789C23A36BA0B8AF65372EB57EA5D89E7"
            "D14E9C7B6B557460F10885DA16AC923F15AF3758F0F03EBD3C5C2C949CBA306D"
            "B44E6A2C076C5F67E281D7EF56785DC4D75945E491F01918800A9E2DC66F6008"
            "0566CE0DAF8D17EAD46AD8E30A247C9F",
            "03",
        ),
        # Index 94 — 1984-bit, exp 3 (test key)
        "94": (
            "ACD2B12302EE644F3F835ABD1FC7A6F62CCE48FFEC622AA8EF062BEF6FB8BA8B"
            "C68BBF6AB5870EED579BC3973E121303D34841A796D6DCBC41DBF9E52C460979"
            "5C0CCF7EE86FA1D5CB041071ED2C51D2202F63F1156C58A92D38BC60BDF424E1"
            "776E2BC9648078A03B36FB554375FC53D57C73F5160EA59F3AFC5398EC7B6775"
            "8D65C9BFF7828B6B82D4BE124A416AB7301914311EA462C19F771F31B3B57336"
            "000DFF732D3B83DE07052D730354D297BEC72871DCCF0E193F171ABA27EE464C"
            "6A97690943D59BDABB2A27EB71CEEBDAFA1176046478FD62FEC452D5CA393296"
            "530AA3F41927ADFE434A2DF2AE3054F8840657A26E0FC617",
            "03",
        ),
        # Index 95 — 1152-bit, exp 3 (test key)
        "95": (
            "BE9E1FA5E9A803852999C4AB432DB28600DCD9DAB76DFAAA47355A0FE37B1508"
            "AC6BF38860D3C6C2E5B12A3CAAF2A7005A7241EBAA7771112C74CF9A0634652F"
            "BCA0E5980C54A64761EA101A114E0F0B5572ADD57D010B7C9C887E104CA4EE12"
            "72DA66D997B9A90B5A6D624AB6C57E73C8F919000EB5F684898EF8C3DBEFB330"
            "C62660BED88EA78E909AFF05F6DA627B",
            "03",
        ),
        # Index 96 — 1024-bit, exp 3
        "96": (
            "B74586D19A207BE6627C5B0AAFBC44A2ECF5A2942D3A26CE19C4FFAEEE920521"
            "868922E893E7838225A3947A2614796FB2C0628CE8C11E3825A56D3B1BBAEF78"
            "3A5C6A81F36F8625395126FA983C5216D3166D48ACDE8A431212FF763A7F79D9"
            "EDB7FED76B485DE45BEB829A3D4730848A366D3324C3027032FF8D16A1E44D8D",
            "03",
        ),
        # Index 97 — 768-bit, exp 3
        "97": (
            "AF0754EAED977043AB6F41D6312AB1E22A6809175BEB28E70D5F99B2DF18CAE7"
            "3519341BBBD327D0B8BE9D4D0E15F07D36EA3E3A05C892F5B19A3E9D3413B0D9"
            "7E7AD10A5F5DE8E38860C0AD004B1E06F4040C295ACB457A788551B6127C0B29",
            "03",
        ),
        # Index 98 — 896-bit, exp 3
        "98": (
            "CA026E52A695E72BD30AF928196EEDC9FAF4A619F2492E3FB31169789C276FFB"
            "B7D43116647BA9E0D106A3542E3965292CF77823DD34CA8EEC7DE367E0807089"
            "5077C7EFAD939924CB187067DBF92CB1E785917BD38BACE0C194CA12DF0CE5B7"
            "A50275AC61BE7C3B436887CA98C9FD39",
            "03",
        ),
        # Index 99 — 1024-bit, exp 3
        "99": (
            "AB79FCC9520896967E776E64444E5DCDD6E13611874F3985722520425295EEA4"
            "BD0C2781DE7F31CD3D041F565F747306EED62954B17EDABA3A6C5B85A1DE1BEB"
            "9A34141AF38FCF8279C9DEA0D5A6710D08DB4124F041945587E20359BAB47B75"
            "75AD94262D4B25F264AF33DEDCF28E09615E937DE32EDC03C54445FE7E382777",
            "03",
        ),
        # Index F3 — 1152-bit, exp 3
        "F3": (
            "98F0C770F23864C2E766DF02D1E833DFF4FFE92D696E1642F0A88C5694C6479D"
            "16DB1537BFE29E4FDC6E6E8AFD1B0EB7EA0124723C333179BF19E93F10658B2F"
            "776E829E87DAEDA9C94A8B3382199A350C077977C97AFF08FD11310AC950A72C"
            "3CA5002EF513FCCC286E646E3C5387535D509514B3B326E1234F9CB48C36DDD4"
            "4B416D23654034A66F403BA511C5EFA3",
            "03",
        ),
    },

    # ── Mastercard (RID A000000004) ───────────────────────────────────────────
    "A000000004": {
        # Index 00 — 768-bit, exp 3 (older production key)
        "00": (
            "9E15214212F6308ACA78B80BD986AC287516846C8D548A9ED0A42E7D997C902C"
            "3E122D1B9DC30995F4E25C75DD7EE0A0CE293B8CC02B977278EF256D761194924"
            "764942FE714FA02E4D57F282BA3B2B62C9E38EF6517823F2CA831BDDF6D363D",
            "03",
        ),
        # Index 01 — 1024-bit, exp 3
        "01": (
            "C696034213D7D8546984579D1D0F0EA519CFF8DEFFC429354CF3A871A6F7183F"
            "1228DA5C7470C055387100CB935A712C4E2864DF5D64BA93FE7E63E71F25B1E5"
            "F5298575EBE1C63AA617706917911DC2A75AC28B251C7EF40F2365912490B939"
            "BCA2124A30A28F54402C34AECA331AB67E1E79B285DD5771B5D9FF79EA630B75",
            "03",
        ),
        # Index 02 — 1536-bit, exp 3 (production)
        "02": (
            "A99A6D3E071889ED9E3A0C391C69B0B804FC160B2B4BDD570C92DD5A0F45F53E"
            "8621F7C96C40224266735E1EE1B3C06238AE35046320FD8E81F8CEB3F8B4C97B"
            "940930A3AC5E790086DAD41A6A4F5117BA1CE2438A51AC053EB002AED866D2C4"
            "58FD73359021A12029A0C043045C11664FE0219EC63C10BF2155BB2784609A10"
            "6421D45163799738C1C30909BB6C6FE52BBB76397B9740CE064A613FF8411185"
            "F08842A423EAD20EDFFBFF1CD6C3FE0C9821479199C26D8572CC8AFFF087A9C3",
            "03",
        ),
        # Index 03 — 1024-bit, exp 3
        "03": (
            "C2490747FE17EB0584C88D47B1602704150ADC88C5B998BD59CE043EDEBF0FFE"
            "E3093AC7956AD3B6AD4554C6DE19A178D6DA295BE15D5220645E3C8131666FA4"
            "BE5B84FE131EA44B039307638B9E74A8C42564F892A64DF1CB15712B736E3374"
            "F1BBB6819371602D8970E97B900793C7C2A89A4A1649A59BE680574DD0B60145",
            "03",
        ),
        # Index 04 — 1152-bit, exp 3
        "04": (
            "A6DA428387A502D7DDFB7A74D3F412BE762627197B25435B7A81716A700157DD"
            "D06F7CC99D6CA28C2470527E2C03616B9C59217357C2674F583B3BA5C7DCF283"
            "8692D023E3562420B4615C439CA97C44DC9A249CFCE7B3BFB22F68228C3AF133"
            "29AA4A613CF8DD853502373D62E49AB256D2BC17120E54AEDCED6D96A4287ACC"
            "5C04677D4A5A320DB8BEE2F775E5FEC5",
            "03",
        ),
        # Index 05 — 1024-bit, exp 3 (first of two MC 05 keys; this is the shorter one)
        "05": (
            "A1F5E1C9BD8650BD43AB6EE56B891EF7459C0A24FA84F9127D1A6C79D4930F6D"
            "B1852E2510F18B61CD354DB83A356BD190B88AB8DF04284D02A4204A7B6CB7C5"
            "551977A9B36379CA3DE1A08E69F301C95CC1C20506959275F41723DD5D292529"
            "0579E5A95B0DF6323FC8E9273D6F849198C4996209166D9BFC973C361CC826E1",
            "03",
        ),
        # Index 06 — 2048-bit, exp 3 (current production key; a 1984-bit variant
        #           also exists: CB26FC83...AB747F)
        "06": (
            "D24C24D2D7FB5509D5B26EBD4077CE74516A2B89E4062D83DC1F7E27D5E5AA66"
            "57F376DABDDB6B4251F323426E621F5DFC1DFA07C06035908B7EDF674CBEB598"
            "F59F9CCB5C55410521C1595E7BD86AD71C42C328FCD9D82C9DD68DF1E6D3F189"
            "C32F578B7E3487E84D642ED2DA3F689AA188C2A1F37E1395732E1872954FFEB1"
            "9D5C404515E7C3F637E4B9E0F889887C0C43194942B3A92D43B0AB091C5510FB"
            "3C24A1264764CBEEBAFEC0AACCA6F948FC973C8950DF934140B7DF87E77193B9"
            "54193EB3B75E60BBB817C4FEEAA542CE388782885B8460C4C9442937ECFDB808"
            "FD8B8979E5368EB859C9068D3D0EA91678D63BC02C87B89DB3EBE6CF1D8F6BE6",
            "03",
        ),
        # Index 09 — 768-bit, exp 3
        "09": (
            "967B6264436C96AA9305776A5919C70DA796340F9997A6C6EF7BEF1D4DBF9CB4"
            "289FB7990ABFF1F3AE692F12844B2452A50AE075FB327976A40E8028F279B1E3"
            "CCB623957D696FC1225CA2EC950E2D415E9AA931FF18B13168D661FBD06F0ABB",
            "03",
        ),
        # Index 22 — 768-bit, exp 3
        "22": (
            "BBE43877CC28C0CE1E14BC14E8477317E218364531D155BB8AC5B63C0D6E284D"
            "D24259193899F9C04C30BAF167D57929451F67AEBD3BBD0D41444501847D8F02"
            "F2C2A2D14817D97AE2625DC163BF8B484C40FFB51749CEDDE9434FB2A0A41099",
            "03",
        ),
        # Index 52 — 1024-bit, exp 65537
        "52": (
            "B831414E0B4613922BD35B4B36802BC1E1E81C95A27C958F5382003DF646154C"
            "A92FC1CE02C3BE047A45E9B02A9089B4B90278237C965192A0FCC86BB49BC82A"
            "E6FDC2DE709006B86C7676EFDF597626FAD633A4F7DC48C445D37EB55FCB3B1A"
            "BB95BAAA826D5390E15FD14ED403FA2D0CB841C650609524EC555E3BC56CA957",
            "010001",
        ),
        # Index EF — 1984-bit, exp 3
        "EF": (
            "A191CB87473F29349B5D60A88B3EAEE0973AA6F1A082F358D849FDDFF9C091F8"
            "99EDA9792CAF09EF28F5D22404B88A2293EEBBC1949C43BEA4D60CFD879A1539"
            "544E09E0F09F60F065B2BF2A13ECC705F3D468B9D33AE77AD9D3F19CA40F23DC"
            "F5EB7C04DC8F69EBA565B1EBCB4686CD274785530FF6F6E9EE43AA43FDB02CE0"
            "0DAEC15C7B8FD6A9B394BABA419D3F6DC85E16569BE8E76989688EFEA2DF22FF"
            "7D35C043338DEAA982A02B866DE5328519EBBCD6F03CDD686673847F84DB651A"
            "B86C28CF1462562C577B853564A290C8556D818531268D25CC98A4CC6A0BDFFF"
            "DA2DCCA3A94C998559E307FDDF915006D9A987B07DDAEB3B",
            "03",
        ),
        # Index F0 — 1024-bit, exp 3
        "F0": (
            "7563C51B5276AA6370AB8405522414645832B6BEF2A989C771475B2E8DC654DC"
            "8A5BFF9E28E31FF1A370A40DC3FFEB06BC85487D5F1CB61C2441FD71CBCD05D8"
            "83F8DE413B243AFC9DCA768B061E35B884B5D21B6B016AA36BA12DABCFE49F8E"
            "528C893C34C7D4793977E4CC99AB09640D9C7AAB7EC5FF3F40E3D4D18DF7E3A7",
            "03",
        ),
        # Index F1 — 1408-bit, exp 3
        "F1": (
            "A0DCF4BDE19C3546B4B6F0414D174DDE294AABBB828C5A834D73AAE27C99B0B0"
            "53A90278007239B6459FF0BBCD7B4B9C6C50AC02CE91368DA1BD21AAEADBC653"
            "47337D89B68F5C99A09D05BE02DD1F8C5BA20E2F13FB2A27C41D3F85CAD5CF66"
            "68E75851EC66EDBF98851FD4E42C44C1D59F5984703B27D5B9F21B8FA0D93279"
            "FBBF69E090642909C9EA27F898959541AA6757F5F624104F6E1D3A9532F2A6E5"
            "1515AEAD1B43B3D7835088A2FAFA7BE7",
            "03",
        ),
        # Index F3 — 1152-bit, exp 3
        "F3": (
            "98F0C770F23864C2E766DF02D1E833DFF4FFE92D696E1642F0A88C5694C6479D"
            "16DB1537BFE29E4FDC6E6E8AFD1B0EB7EA0124723C333179BF19E93F10658B2F"
            "776E829E87DAEDA9C94A8B3382199A350C077977C97AFF08FD11310AC950A72C"
            "3CA5002EF513FCCC286E646E3C5387535D509514B3B326E1234F9CB48C36DDD4"
            "4B416D23654034A66F403BA511C5EFA3",
            "03",
        ),
        # Index F5 — 1984-bit, exp 65537
        "F5": (
            "A6E6FB72179506F860CCCA8C27F99CECD94C7D4F3191D303BBEE37481C7AA15F"
            "233BA755E9E4376345A9A67E7994BDC1C680BB3522D8C93EB0CCC91AD31AD450"
            "DA30D337662D19AC03E2B4EF5F6EC18282D491E19767D7B24542DFDEFF6F6218"
            "5503532069BBB369E3BB9FB19AC6F1C30B97D249EEE764E0BAC97F25C873D973"
            "953E5153A42064BBFABFD06A4BB486860BF6637406C9FC36813A4A75F75C31CC"
            "A9F69F8DE59ADECEF6BDE7E07800FCBE035D3176AF8473E23E9AA3DFEE221196"
            "D1148302677C720CFE2544A03DB553E7F1B8427BA1CC72B0F29B12DFEF4C081D"
            "076D353E71880AADFF386352AF0AB7B28ED49E1E672D11F9",
            "010001",
        ),
        # Index F6 — 1792-bit, exp 3
        "F6": (
            "A25A6BD783A5EF6B8FB6F83055C260F5F99EA16678F3B9053E0F6498E82C3F5D"
            "1E8C38F13588017E2B12B3D8FF6F50167F46442910729E9E4D1B3739E5067C0A"
            "C7A1F4487E35F675BC16E233315165CB142BFDB25E301A632A54A3371EBAB657"
            "2DEEBAF370F337F057EE73B4AE46D1A8BC4DA853EC3CC12C8CBC2DA18322D685"
            "30C70B22BDAC351DD36068AE321E11ABF264F4D3569BB71214545005558DE260"
            "83C735DB776368172FE8C2F5C85E8B5B890CC682911D2DE71FA626B8817FCCC0"
            "8922B703869F3BAEAC1459D77CD85376BC36182F4238314D6C4212FBDD7F23D3",
            "03",
        ),
        # Index F7 — 1024-bit, exp 65537
        "F7": (
            "94EA62F6D58320E354C022ADDCF0559D8CF206CD92E869564905CE21D720F971B"
            "7AEA374830EBE1757115A85E088D41C6B77CF5EC821F30B1D890417BF2FA31E5"
            "908DED5FA677F8C7B184AD09028FDDE96B6A6109850AA800175EABCDBBB684A9"
            "6C2EB6379DFEA08D32FE2331FE103233AD58DCDB1E6E077CB9F24EAEC5C25AF",
            "010001",
        ),
        # Index F8 — 1024-bit, exp 3
        "F8": (
            "A1F5E1C9BD8650BD43AB6EE56B891EF7459C0A24FA84F9127D1A6C79D4930F6D"
            "B1852E2510F18B61CD354DB83A356BD190B88AB8DF04284D02A4204A7B6CB7C5"
            "551977A9B36379CA3DE1A08E69F301C95CC1C20506959275F41723DD5D292529"
            "0579E5A95B0DF6323FC8E9273D6F849198C4996209166D9BFC973C361CC826E1",
            "03",
        ),
        # Index F9 — 1536-bit, exp 3
        "F9": (
            "A99A6D3E071889ED9E3A0C391C69B0B804FC160B2B4BDD570C92DD5A0F45F53E"
            "8621F7C96C40224266735E1EE1B3C06238AE35046320FD8E81F8CEB3F8B4C97B"
            "940930A3AC5E790086DAD41A6A4F5117BA1CE2438A51AC053EB002AED866D2C4"
            "58FD73359021A12029A0C043045C11664FE0219EC63C10BF2155BB2784609A10"
            "6421D45163799738C1C30909BB6C6FE52BBB76397B9740CE064A613FF8411185"
            "F08842A423EAD20EDFFBFF1CD6C3FE0C9821479199C26D8572CC8AFFF087A9C3",
            "03",
        ),
        # Index FA — 1152-bit, exp 3
        "FA": (
            "A90FCD55AA2D5D9963E35ED0F440177699832F49C6BAB15CDAE5794BE93F934D"
            "4462D5D12762E48C38BA83D8445DEAA74195A301A102B2F114EADA0D180EE5E7"
            "A5C73E0C4E11F67A43DDAB5D55683B1474CC0627F44B8D3088A492FFAADAD4F4"
            "2422D0E7013536C3C49AD3D0FAE96459B0F6B1B6056538A3D6D44640F94467B"
            "108867DEC40FAAECD740C00E2B7A8852D",
            "03",
        ),
        # Index FB — 1024-bit, exp 2 (legacy Europay/Mastercard)
        "FB": (
            "A9548DFB398B48123FAF41E6CFA4AE1E2352B518AB4BCEFECDB0B3EDEC090287"
            "D88B12259F361C1CC088E5F066494417E8EE8BBF8991E2B32FF16F994697842B"
            "3D6CB37A2BB5742A440B6356C62AA33DB3C455E59EDDF7864701D03A5B83EE9E"
            "9BD83AB93302AC2DFE63E66120B051CF081F56326A71303D952BB336FF12610D",
            "02",
        ),
        # Index FC — 896-bit, exp 2 (legacy Europay/Mastercard)
        "FC": (
            "B37BFD2A9674AD6221C1A001081C62653DC280B0A9BD052C677C913CE7A0D902E"
            "77B12F4D4D79037B1E9B923A8BB3FAC3C612045BB3914F8DF41E9A1B61BFA5B4"
            "1705A691D09CE6F530FE48B30240D98F4E692FFD6AADB87243BA8597AB237586"
            "ECF258F4148751BE5DA5A3BE6CC34BD",
            "02",
        ),
        # Index FD — 768-bit, exp 2 (legacy Europay/Mastercard)
        "FD": (
            "B3572BA49AE4C7B7A0019E5189E142CFCDED9498DDB5F0470567AB0BA713B8DA"
            "226424622955B54B937ABFEFAAD97919E377621E22196ABC1419D5ADC12348420"
            "9EA7CB7029E66A0D54C5B45C8AD615AEDB6AE9E0A2F75310EA8961287241245",
            "02",
        ),
        # Index FE — 1024-bit, exp 3
        "FE": (
            "A653EAC1C0F786C8724F737F172997D63D1C3251C44402049B865BAE877D0F39"
            "8CBFBE8A6035E24AFA086BEFDE9351E54B95708EE672F0968BCD50DCE40F7833"
            "22B2ABA04EF137EF18ABF03C7DBC5813AEAEF3AA7797BA15DF7D5BA1CBAF7FD5"
            "20B5A482D8D3FEE105077871113E23A49AF3926554A70FE10ED728CF793B62A1",
            "03",
        ),
        # Index FF — 896-bit, exp 3
        "FF": (
            "B855CC64313AF99C453D181642EE7DD21A67D0FF50C61FE213BCDC18AFBCD077"
            "22EFDD2594EFDC227DA3DA23ADCC90E3FA907453ACC954C47323BEDCF8D4862C"
            "457D25F47B16D7C3502BE081913E5B0482D838484065DA5F6659E00A9E5D570A"
            "DA1EC6AF8C57960075119581FC81468D",
            "03",
        ),
    },
}


def get_ca_public_key(rid: str, key_index: int | str) -> tuple[bytes, bytes] | None:
    """
    Look up an EMV CA public key by RID and key index.

    Args:
        rid:       5-byte RID as uppercase hex string, e.g. "A000000003"
        key_index: Key index as integer or hex string, e.g. 9 or "09"

    Returns:
        (modulus_bytes, exponent_bytes) or None if not found.
    """
    rid = rid.upper().replace(" ", "")[:10]
    if isinstance(key_index, int):
        idx = f"{key_index:02X}"
    else:
        idx = str(key_index).upper().lstrip("0") or "0"
        idx = f"{int(idx, 16):02X}"

    network_keys = EMV_CA_KEYS.get(rid)
    if not network_keys:
        return None

    entry = network_keys.get(idx)
    if not entry:
        return None

    mod_hex, exp_hex = entry
    mod_bytes = bytes.fromhex(mod_hex)
    exp_bytes = bytes.fromhex(exp_hex)
    return mod_bytes, exp_bytes


# Global verbose flag
VERBOSE = False

def vprint(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)

def bcd_byte(b: int) -> int:
    """Convert a BCD-encoded byte to an integer. E.g. 0x26 → 26."""
    return (b >> 4) * 10 + (b & 0x0F)

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

        # Expiry (5F24 = YYMMDD in BCD)
        exp = self.data.get('5F24')
        if exp:
            if len(exp) == 3:
                yy = bcd_byte(exp[0])
                mm = bcd_byte(exp[1])
                info['expiry'] = f"{mm:02d}/20{yy:02d}"
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
# RSA Certificate Chain Decoder  (EMV Book 2, Section 6)
# ──────────────────────────────────────────────────────────────────────────────

def _rsa_recover(cert_bytes: bytes, modulus: bytes, exp_bytes: bytes) -> bytes | None:
    """Perform RSA public operation: cert^e mod n → recovered bytes."""
    try:
        n = int.from_bytes(modulus, 'big')
        e = int.from_bytes(exp_bytes, 'big')
        c = int.from_bytes(cert_bytes, 'big')
        r = pow(c, e, n)
        return r.to_bytes(len(modulus), 'big')
    except Exception:
        return None


def decode_issuer_pk_cert(
    cert: bytes,
    ca_modulus: bytes,
    ca_exp: bytes,
    issuer_pk_rem: bytes | None = None,
    issuer_pk_exp: bytes | None = None,
) -> dict | None:
    """
    Decode the Issuer Public Key Certificate (EMV tag 90).

    Per EMV Book 2 §6.3:
      Header (1) | Format=0x02 (1) | IssuerID (4) | ExpDate (2) | SerNo (3) |
      HashAlgo (1) | PKAlgo (1) | IssuerPKLen (1) | IssuerPKExpLen (1) |
      IssuerPK_LeftmostDigits (NCA-36) | Hash (20) | Trailer=0xBC (1)

    Returns dict with 'modulus', 'exponent', 'issuer_id', 'expiry', and 'valid'.
    """
    if len(cert) != len(ca_modulus):
        vprint(f"  [cert] Issuer PK cert len {len(cert)} != CA modulus len {len(ca_modulus)}")
        return None

    recovered = _rsa_recover(cert, ca_modulus, ca_exp)
    if not recovered:
        return None

    if recovered[0] != 0x6A or recovered[-1] != 0xBC:
        vprint(f"  [cert] Bad header/trailer: {recovered[0]:02X}...{recovered[-1]:02X}")
        return None
    if recovered[1] != 0x02:
        vprint(f"  [cert] Wrong format byte: {recovered[1]:02X} (expected 02)")
        return None

    n_ca = len(ca_modulus)
    issuer_id    = recovered[2:6]
    expiry       = recovered[6:8]
    serial       = recovered[8:11]
    hash_algo    = recovered[11]
    pk_algo      = recovered[12]
    iss_pk_len   = recovered[13]
    iss_pk_exp_len = recovered[14]
    leftmost     = recovered[15 : n_ca - 21]   # n_ca - 36 bytes
    hash_in_cert = recovered[n_ca - 21 : n_ca - 1]

    # Assemble Issuer PK modulus
    if issuer_pk_rem:
        modulus = leftmost + issuer_pk_rem
    else:
        modulus = leftmost

    # Trim or verify length
    modulus = modulus[:iss_pk_len]

    if len(modulus) < 8:
        return None

    exp = issuer_pk_exp or bytes([3])

    result = {
        'valid': True,
        'issuer_id': issuer_id.hex().upper(),
        'expiry': f"{bcd_byte(expiry[0]):02d}/20{bcd_byte(expiry[1]):02d}",  # MMYY BCD → MM/20YY
        'serial': serial.hex().upper(),
        'modulus': modulus,
        'exponent': exp,
        'modulus_bits': len(modulus) * 8,
        'hash_in_cert': hash_in_cert.hex().upper(),
    }
    vprint(f"  [cert] Issuer PK decoded: {len(modulus)*8}-bit, issuer={result['issuer_id']}, exp={result['expiry']}")
    return result


def decode_icc_pk_cert(
    cert: bytes,
    issuer_modulus: bytes,
    issuer_exp: bytes,
    icc_pk_rem: bytes | None = None,
    icc_pk_exp: bytes | None = None,
) -> dict | None:
    """
    Decode the ICC Public Key Certificate (EMV tag 9F46).

    Per EMV Book 2 §6.4:
      Header (1) | Format=0x04 (1) | PAN (10) | ExpDate (2) | SerNo (3) |
      HashAlgo (1) | PKAlgo (1) | ICCPKLen (1) | ICCPKExpLen (1) |
      ICCPK_LeftmostDigits (NISS-42) | Hash (20) | Trailer=0xBC (1)

    Returns dict with 'modulus', 'exponent', 'pan', 'expiry', and 'valid'.
    """
    n_iss = len(issuer_modulus)

    if len(cert) != n_iss:
        vprint(f"  [cert] ICC PK cert len {len(cert)} != Issuer modulus len {n_iss}")
        return None

    recovered = _rsa_recover(cert, issuer_modulus, issuer_exp)
    if not recovered:
        return None

    if recovered[0] != 0x6A or recovered[-1] != 0xBC:
        vprint(f"  [cert] ICC Bad header/trailer: {recovered[0]:02X}...{recovered[-1]:02X}")
        return None
    if recovered[1] != 0x04:
        vprint(f"  [cert] ICC wrong format byte: {recovered[1]:02X} (expected 04)")
        return None

    pan_raw      = recovered[2:12]
    expiry       = recovered[12:14]
    serial       = recovered[14:17]
    hash_algo    = recovered[17]
    pk_algo      = recovered[18]
    icc_pk_len   = recovered[19]
    icc_pk_exp_len = recovered[20]
    leftmost     = recovered[21 : n_iss - 21]  # n_iss - 42 bytes
    hash_in_cert = recovered[n_iss - 21 : n_iss - 1]

    # Pan (BCD, strip FF padding)
    pan_hex = pan_raw.hex().upper().rstrip('F')

    # Assemble ICC PK modulus
    if icc_pk_rem:
        modulus = leftmost + icc_pk_rem
    else:
        modulus = leftmost

    modulus = modulus[:icc_pk_len]

    if len(modulus) < 8:
        return None

    exp = icc_pk_exp or bytes([3])

    result = {
        'valid': True,
        'pan': pan_hex,
        'expiry': f"{bcd_byte(expiry[0]):02d}/20{bcd_byte(expiry[1]):02d}",  # MMYY BCD
        'serial': serial.hex().upper(),
        'modulus': modulus,
        'exponent': exp,
        'modulus_bits': len(modulus) * 8,
        'hash_in_cert': hash_in_cert.hex().upper(),
    }
    vprint(f"  [cert] ICC PK decoded: {len(modulus)*8}-bit, pan={pan_hex}, exp={result['expiry']}")
    return result


def decode_cert_chain(card_data: dict, rid: str) -> dict:
    """
    Decode the full EMV certificate chain: CA → Issuer PK → ICC PK.

    Returns a dict with keys:
      'ca_key_index', 'issuer_pk', 'icc_pk', 'icc_public_key_pem',
      'error' (if something failed)
    """
    result: dict = {}

    ca_idx_byte = card_data.get('8F')
    if not ca_idx_byte:
        result['error'] = "No CA key index (tag 8F) found in card data"
        return result

    ca_idx = ca_idx_byte[0]
    result['ca_key_index'] = ca_idx

    ca_key = get_ca_public_key(rid, ca_idx)
    if not ca_key:
        result['error'] = f"CA public key not found: RID={rid} index={ca_idx:#04x}"
        return result

    ca_modulus, ca_exp = ca_key
    result['ca_modulus_bits'] = len(ca_modulus) * 8

    # ── Step 1: Decode Issuer PK Certificate ────────────────────────────────
    iss_cert = card_data.get('90')
    if not iss_cert:
        result['error'] = "No Issuer PK Certificate (tag 90) found"
        return result

    iss_pk_rem = card_data.get('92') or card_data.get('9F2B')
    iss_pk_exp = card_data.get('9F32')

    issuer = decode_issuer_pk_cert(iss_cert, ca_modulus, ca_exp, iss_pk_rem, iss_pk_exp)
    if not issuer:
        result['error'] = "Failed to decode Issuer PK Certificate — CA key mismatch or bad cert"
        return result

    result['issuer_pk'] = {
        'modulus_bits': issuer['modulus_bits'],
        'issuer_id': issuer['issuer_id'],
        'expiry': issuer['expiry'],
        'serial': issuer['serial'],
    }

    # ── Step 2: Decode ICC PK Certificate ───────────────────────────────────
    icc_cert = card_data.get('9F46')
    if not icc_cert:
        result['error'] = "No ICC PK Certificate (tag 9F46) — card may be SDA only"
        result['issuer_pk_decoded'] = True
        return result

    icc_pk_rem = card_data.get('9F48')
    icc_pk_exp = card_data.get('9F47')

    icc = decode_icc_pk_cert(icc_cert, issuer['modulus'], issuer['exponent'],
                              icc_pk_rem, icc_pk_exp)
    if not icc:
        result['error'] = "Failed to decode ICC PK Certificate — Issuer key mismatch or bad cert"
        return result

    result['icc_pk'] = {
        'modulus_bits': icc['modulus_bits'],
        'pan': icc['pan'],
        'expiry': icc['expiry'],
        'serial': icc['serial'],
    }

    # Build RSA public key object
    try:
        n = int.from_bytes(icc['modulus'], 'big')
        e = int.from_bytes(icc['exponent'], 'big')
        pub_nums = RSAPublicNumbers(e, n)
        pub_key = pub_nums.public_key(default_backend())
        pem = pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        result['icc_public_key_pem'] = pem
        result['icc_modulus'] = icc['modulus']
        result['icc_exponent'] = icc['exponent']
    except Exception as ex:
        result['error'] = f"Could not build RSA key object: {ex}"

    return result


def decode_emv_cert(cert_bytes: bytes, modulus: bytes, exp_bytes: bytes) -> dict | None:
    """Legacy helper: RSA public op + header/trailer check."""
    recovered = _rsa_recover(cert_bytes, modulus, exp_bytes)
    if not recovered:
        return None
    if recovered[0] != 0x6A or recovered[-1] != 0xBC:
        return None
    return {'format': recovered[1], 'recovered': recovered, 'valid': True}


def extract_icc_public_key_from_cert(cert_bytes: bytes, modulus: bytes,
                                      exp_bytes: bytes, remainder: bytes | None,
                                      icc_exp: bytes) -> RSAPublicNumbers | None:
    """Legacy wrapper — calls the new decode_icc_pk_cert."""
    icc = decode_icc_pk_cert(cert_bytes, modulus, exp_bytes, remainder, icc_exp)
    if not icc:
        return None
    try:
        n = int.from_bytes(icc['modulus'], 'big')
        e = int.from_bytes(icc['exponent'], 'big')
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




def build_dol_data(dol: bytes) -> tuple[bytes, bytes]:
    """
    Parse a Data Object List (DOL) and return (filled_data, unpredictable_number).
    Fills tag 9F37 (Unpredictable Number) with random bytes; other tags with zeros.
    Returns the DOL response data and the 4-byte unpredictable number used.
    """
    un = _os.urandom(4)
    result = []
    i = 0
    while i < len(dol):
        # Read tag (multi-byte)
        tag = dol[i]; i += 1
        if (tag & 0x1F) == 0x1F:
            tag = (tag << 8) | dol[i]; i += 1
            while i < len(dol) and (dol[i-1] & 0x80):
                tag = (tag << 8) | dol[i]; i += 1
        if i >= len(dol):
            break
        length = dol[i]; i += 1
        tag_hex = format(tag, 'X').zfill(4 if tag > 0xFF else 2)
        if tag_hex == '9F37':  # Unpredictable Number → use our random bytes
            result.extend(list(un[:length]))
        else:
            result.extend([0x00] * length)
    return bytes(result), un


def sign_with_card(card: CardInterface, ddol: bytes | None = None) -> tuple[bytes | None, bytes]:
    """
    Use INTERNAL AUTHENTICATE (DDA) to get a Signed Dynamic Application Data (SDAD).

    The DDOL (Dynamic Data Object List) describes what data the terminal must provide.
    For most Visa DDA cards the DDOL is just tag 9F37 (Unpredictable Number, 4 bytes).

    Returns (sdad_bytes, auth_data) — auth_data includes the Unpredictable Number used,
    needed to verify the SDAD. Returns (None, auth_data) on failure.
    """
    if ddol:
        auth_data, un = build_dol_data(ddol)
    else:
        # Default: 4-byte Unpredictable Number (covers most Visa/MC DDA cards)
        auth_data = un = _os.urandom(4)

    apdu = [0x00, 0x88, 0x00, 0x00, len(auth_data)] + list(auth_data) + [0x00]
    resp, sw1, sw2 = card.send_soft(apdu)

    if (sw1, sw2) == (0x90, 0x00):
        tlv = TLV.parse(resp)
        # Tag 9F4B = SDAD (explicit DDA response in TLV format)
        # Tag 80   = Response Template Format 1 (raw SDAD bytes, no inner TLV)
        sdad = tlv.get('9F4B') or tlv.get('80') or resp
        vprint(f"  SDAD raw ({len(sdad)} bytes): {sdad.hex().upper()[:40]}...")
        return sdad, auth_data

    vprint(f"  INTERNAL AUTHENTICATE failed: SW={sw1:02X}{sw2:02X}")
    return None, auth_data


def verify_sdad(sdad: bytes, auth_data: bytes, icc_pk_pem: bytes) -> dict:
    """
    Verify a Signed Dynamic Application Data (SDAD) produced by INTERNAL AUTHENTICATE.

    EMV Book 2 §6.6 SDAD format:
      6A | 05 | Hash Algo (1) | ICC Dynamic Data Len (1) | ICC Dynamic Data |
      Padding (0xBB...) | Hash (20) | BC

    The hash covers: 05 | ICC Dynamic Data | auth_data (DDOL response)
    """
    try:
        pub_key = serialization.load_pem_public_key(icc_pk_pem)
        n = pub_key.public_numbers().n
        e = pub_key.public_numbers().e
        key_len = (n.bit_length() + 7) // 8

        if len(sdad) != key_len:
            return {'valid': False, 'error': f"SDAD length {len(sdad)} != ICC key length {key_len}"}

        # RSA public operation
        sig_int = int.from_bytes(sdad, 'big')
        rec_int = pow(sig_int, e, n)
        recovered = rec_int.to_bytes(key_len, 'big')

        if recovered[0] != 0x6A or recovered[-1] != 0xBC:
            return {'valid': False,
                    'error': f"Bad SDAD header/trailer: {recovered[0]:02X}...{recovered[-1]:02X}"}

        if recovered[1] != 0x05:
            return {'valid': False,
                    'error': f"Wrong format byte {recovered[1]:02X} (expected 05 for SDAD)"}

        hash_algo    = recovered[2]
        dd_len       = recovered[3]
        icc_dd       = recovered[4 : 4 + dd_len]
        pad_start    = 4 + dd_len
        pad_end      = key_len - 21   # 20 bytes hash + 1 byte trailer
        pad_pattern  = recovered[pad_start : pad_end]
        hash_in_sdad = recovered[pad_end : pad_end + 20]

        # EMV Book 2 §6.6.2: Hash input =
        #   Signed Data Format (05) | Hash Algo | ICC DD Len | ICC Dynamic Data |
        #   Pad Pattern (0xBB...) | Terminal Dynamic Data (auth_data)
        hash_input = (bytes([0x05, hash_algo, dd_len]) + icc_dd + pad_pattern + auth_data)
        expected_hash = hashlib.sha1(hash_input).digest()
        hash_ok = (expected_hash == hash_in_sdad)

        # ICC Dynamic Data inner structure: idn_len | ICC_Dynamic_Number | ...
        icc_dynamic_number = None
        if icc_dd:
            idn_len = icc_dd[0]
            icc_dynamic_number = icc_dd[1 : 1 + idn_len] if len(icc_dd) > idn_len else icc_dd[1:]

        vprint(f"  SDAD hash input ({len(hash_input)} bytes): {hash_input.hex().upper()[:60]}...")
        vprint(f"  SDAD hash in cert:  {hash_in_sdad.hex().upper()}")
        vprint(f"  SDAD expected hash: {expected_hash.hex().upper()}")

        return {
            'valid': True,
            'format': 0x05,
            'hash_algo': hash_algo,
            'icc_dynamic_number': icc_dynamic_number,
            'icc_dynamic_data': icc_dd,
            'hash_ok': hash_ok,
            'hash_in_sdad': hash_in_sdad.hex().upper(),
            'expected_hash': expected_hash.hex().upper(),
        }

    except Exception as ex:
        return {'valid': False, 'error': str(ex)}



# ──────────────────────────────────────────────────────────────────────────────
# Reader / Connection Management
# ──────────────────────────────────────────────────────────────────────────────

def get_card_connection(reader_index: int = 0):
    """Connect to a card via PC/SC. Auto-escalates to sudo if polkit denies access."""
    if not PYSCARD_AVAILABLE:
        raise RuntimeError("pyscard not available. Install with: pip install pyscard")

    try:
        available = readers()
    except Exception as e:
        err_str = str(e)
        if ("Access denied" in err_str or "0x8010006A" in err_str) and os.getuid() != 0:
            # pcscd polkit authorization failed — re-exec with sudo
            print("  [!] pcscd requires elevated access (polkit). Re-running with sudo...")
            sys.stdout.flush()
            import subprocess
            import shutil
            script_path = os.path.abspath(sys.argv[0])
            uv_bin = shutil.which('uv') or '/usr/sbin/uv'
            cmd = ['sudo', uv_bin, 'run', script_path] + sys.argv[1:]
            result = subprocess.run(cmd, check=False)
            sys.exit(result.returncode)
        raise RuntimeError(
            f"PC/SC error: {e}\n"
            "  - Ensure pcscd is running: sudo systemctl start pcscd\n"
            "  - Try: sudo uv run emv-pki.py <command>\n"
            "  - Use --demo for simulation mode"
        )

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

    chain = None
    conn = get_card_connection(args.reader)
    card_iface = CardInterface(conn)
    emv = EMVCard(card_iface)
    print("  Reading card...")
    if not emv.read_all(scan_all=True):
        print("  [ERROR] Failed to read card.")
        sys.exit(1)
    info = emv.get_info()
    # Attempt full certificate chain decode
    if emv.aid:
        rid = emv.aid[:5].hex().upper()
        chain = decode_cert_chain(emv.data, rid)

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
    print(f"  ICC PK Cert:     {'Present (' + str(info['icc_pk_cert_len']) + ' bytes)' if info.get('icc_pk_cert_len') else 'Not found (SDA only)'}")
    if info.get('ca_key_index') is not None:
        print(f"  CA Key Index:    {info['ca_key_index']:#04x}")

    if chain:
        print(f"\n  ─── Certificate Chain Decode ───")
        if chain.get('ca_modulus_bits'):
            print(f"  CA key:          {chain['ca_modulus_bits']}-bit (index {chain.get('ca_key_index', '?'):#04x})")
        if chain.get('issuer_pk'):
            ipk = chain['issuer_pk']
            print(f"  Issuer PK:       {ipk['modulus_bits']}-bit  issuer={ipk['issuer_id']}  exp={ipk['expiry']}")
        if chain.get('icc_pk'):
            cpk = chain['icc_pk']
            print(f"  ICC PK:          {cpk['modulus_bits']}-bit  exp={cpk['expiry']}  serial={cpk['serial']}")
            print(f"  Chain decode:    OK — ICC public key recovered!")
        if chain.get('error') and not chain.get('icc_pk'):
            print(f"  Chain decode:    {chain['error']}")

    if info.get('has_pin_encipherment_key'):
        print(f"  PIN Enc. Key:    Present")
    if info.get('note'):
        print(f"\n  Note: {info['note']}")

    if hasattr(args, 'json') and args.json:
        safe = {k: v for k, v in info.items() if not k.startswith('_') and not isinstance(v, bytes)}
        if chain:
            safe['chain'] = {k: v for k, v in chain.items() if not isinstance(v, bytes)}
        print("\n" + json.dumps(safe, indent=2))

    print()


def cmd_export(args):
    """Export card's ICC public key in PEM format."""
    print("\n━━━ Export ICC Public Key ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    conn = get_card_connection(args.reader)
    card_iface = CardInterface(conn)
    emv = EMVCard(card_iface)
    print("  Reading card...")
    if not emv.read_all(scan_all=True):
        print("  [ERROR] Failed to read card.")
        sys.exit(1)

    info = emv.get_info()
    network = info.get('network', 'Unknown')
    pan_masked = info.get('pan_masked', 'N/A')

    rid = emv.aid[:5].hex().upper() if emv.aid else ''
    chain = decode_cert_chain(emv.data, rid)

    if chain.get('icc_public_key_pem'):
        pem = chain['icc_public_key_pem']
        icc_info = chain.get('icc_pk', {})
        iss_info = chain.get('issuer_pk', {})
        key_info = (f"RSA-{icc_info.get('modulus_bits','?')} "
                    f"(Issuer: {iss_info.get('issuer_id','?')}, "
                    f"CA index: {chain.get('ca_key_index', '?'):#04x})")
        print(f"  Certificate chain decoded successfully.")
        print(f"  Issuer PK: {iss_info.get('modulus_bits','?')}-bit, expires {iss_info.get('expiry','?')}")
        print(f"  ICC    PK: {icc_info.get('modulus_bits','?')}-bit, expires {icc_info.get('expiry','?')}")
    elif chain.get('error'):
        print(f"  [ERROR] {chain['error']}")
        print("  Cannot produce a cryptographically verified ICC public key.")
        sys.exit(1)
    else:
        print("  [ERROR] Certificate chain decode returned no key.")
        sys.exit(1)

    out_path = args.output or "card_pubkey.pem"
    with open(out_path, 'wb') as f:
        f.write(pem)

    print(f"\n  Network:  {network}")
    print(f"  Card:     {pan_masked}")
    print(f"  Key:      {key_info}")
    print(f"  Saved:    {out_path}")
    print(f"\n  Public Key:\n")
    print(pem.decode())


def cmd_encrypt(args):
    """Encrypt data to the card's ICC public key (RSA-OAEP hybrid)."""
    print("\n━━━ Encrypt Data ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    # Read ICC public key live from card
    conn = get_card_connection(args.reader)
    card_iface = CardInterface(conn)
    emv = EMVCard(card_iface)
    print("  Reading card...")
    emv.read_all(scan_all=True)

    info = emv.get_info()
    pan_masked = info.get('pan_masked', 'N/A')
    network = info.get('network', 'Unknown')

    rid = emv.aid[:5].hex().upper() if emv.aid else ''
    chain = decode_cert_chain(emv.data, rid)
    if not chain.get('icc_public_key_pem'):
        print(f"  [ERROR] {chain.get('error', 'Could not recover ICC public key')}")
        sys.exit(1)
    pem = chain['icc_public_key_pem']
    icc_bits = chain.get('icc_pk', {}).get('modulus_bits', '?')
    print(f"  Card:     {pan_masked}  ({network})")
    print(f"  ICC key:  RSA-{icc_bits} (from certificate chain)")

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
    bundle['card_id'] = pan_masked  # so decrypt can verify card identity

    out_path = args.output or "encrypted.json"
    with open(out_path, 'w') as f:
        json.dump(bundle, f, indent=2)

    print(f"\n  ✓ Encrypted {len(plaintext)} bytes")
    print(f"  ✓ Saved to: {out_path}")
    print(f"\n  Bundle preview:")
    print(f"    scheme:        {bundle['scheme']}")
    print(f"    card_id:       {bundle['card_id']}")
    print(f"    encrypted_key: {bundle['encrypted_key'][:40]}...")
    print(f"    nonce:         {bundle['nonce']}")
    print(f"    ciphertext:    {bundle['ciphertext'][:40]}...")


def cmd_decrypt(args):
    """Decrypt data using card's PSO:DECIPHER command (ISO 7816-8)."""
    print("\n━━━ Decrypt Data ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    if not args.input:
        print("  Provide --input encrypted.json")
        sys.exit(1)

    with open(args.input) as f:
        bundle = json.load(f)

    print(f"  Scheme:  {bundle.get('scheme', 'unknown')}")
    if bundle.get('card_id'):
        print(f"  Card ID: {bundle['card_id']}")

    # Establish full EMV context (required before PSO:DECIPHER)
    conn = get_card_connection(args.reader)
    card_iface = CardInterface(conn)
    emv = EMVCard(card_iface)
    print("  Initialising EMV context (SELECT → GPO → READ RECORDS)...")
    if not emv.read_all(scan_all=False):
        print("  [ERROR] Failed to initialise card.")
        sys.exit(1)

    info = emv.get_info()
    pan_masked = info.get('pan_masked', 'N/A')
    print(f"  Card:    {pan_masked}  ({info.get('network', 'Unknown')})")

    # Verify card identity matches the bundle (advisory)
    if bundle.get('card_id') and bundle['card_id'] != pan_masked:
        print(f"  [WARN] Bundle card_id {bundle['card_id']} does not match this card {pan_masked}")

    encrypted_key = base64.b64decode(bundle['encrypted_key'])

    # ISO 7816-8 PSO:DECIPHER:
    #   CLA=00 INS=2A P1=80 P2=86
    #   Data = 0x00 (padding indicator: OAEP) || RSA-encrypted-AES-key
    #   Le = 00 (all bytes)
    padding_indicator = [0x00]
    data_field = padding_indicator + list(encrypted_key)
    lc = len(data_field)

    # Extended length may be needed for large keys
    if lc <= 255:
        apdu = [0x00, 0x2A, 0x80, 0x86, lc] + data_field + [0x00]
    else:
        # Extended APDU: 00 2A 80 86 00 [Lc_hi] [Lc_lo] [data] 00 00
        apdu = ([0x00, 0x2A, 0x80, 0x86, 0x00, (lc >> 8) & 0xFF, lc & 0xFF]
                + data_field + [0x00, 0x00])

    print(f"  Sending PSO:DECIPHER  ({lc} bytes data field, key={len(encrypted_key)} bytes)...")
    resp, sw1, sw2 = card_iface.send_soft(apdu)
    sw = (sw1 << 8) | sw2

    _SW_NAMES = {
        0x9000: "Success",
        0x6D00: "Instruction not supported (card does not implement PSO:DECIPHER)",
        0x6A81: "Function not supported",
        0x6985: "Conditions of use not satisfied (transaction context required?)",
        0x6982: "Security status not satisfied (PIN required?)",
        0x6984: "Referenced data not usable",
        0x6800: "Function in CLA not supported",
        0x6700: "Wrong length (Lc/Le incorrect)",
    }
    sw_desc = _SW_NAMES.get(sw, "Unknown status")
    print(f"  PSO:DECIPHER response: SW={sw1:02X}{sw2:02X}  ({sw_desc})")
    if resp:
        print(f"  Response data: {bytes(resp).hex().upper()}")

    if sw != 0x9000:
        print(f"\n  ✗ Decryption failed — SW={sw1:02X}{sw2:02X}")
        print(f"  This card does not support RSA decryption via PSO:DECIPHER.")
        print(f"  The card's private key is accessible only through INTERNAL AUTHENTICATE (signing).")
        print(f"  Run `probe` to see a full capability report.")
        sys.exit(1)

    # Card returned the decrypted AES key
    aes_key = bytes(resp)
    if len(aes_key) < 32:
        print(f"  [ERROR] Decrypted key too short ({len(aes_key)} bytes, expected ≥32)")
        sys.exit(1)

    nonce      = base64.b64decode(bundle['nonce'])
    ciphertext = base64.b64decode(bundle['ciphertext'])
    try:
        plaintext = AESGCM(aes_key[:32]).decrypt(nonce, ciphertext, None)
    except Exception as e:
        print(f"  [ERROR] AES-GCM decryption failed: {e}")
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
    """Sign data using card's INTERNAL AUTHENTICATE (DDA)."""
    print("\n━━━ Sign Data with Card ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    conn = get_card_connection(args.reader)
    card_iface = CardInterface(conn)
    emv = EMVCard(card_iface)
    print("  Reading card and initiating DDA flow...")
    emv.read_all(scan_all=True)

    ddol = emv.data.get('9F49')  # DDOL from card
    if ddol:
        print(f"  DDOL: {ddol.hex().upper()}")
    else:
        print("  DDOL: not present (using default: 4-byte Unpredictable Number)")

    print("  Requesting SDAD (INTERNAL AUTHENTICATE)...")
    sig, auth_data = sign_with_card(card_iface, ddol)
    if not sig:
        print("  [ERROR] Card did not respond to INTERNAL AUTHENTICATE.")
        print("  Check that the card supports DDA (AIP bit 13 must be set).")
        aip = emv.data.get('82')
        if aip and len(aip) >= 2:
            aip_val = (aip[0] << 8) | aip[1]
            print(f"  AIP = {aip.hex().upper()}: DDA={'Yes' if aip_val & 0x2000 else 'No'}")
        sys.exit(1)

    # Get ICC public key for verification display
    rid = emv.aid[:5].hex().upper() if emv.aid else ''
    chain = decode_cert_chain(emv.data, rid)
    icc_pk_pem = chain.get('icc_public_key_pem')
    network = emv.network

    print(f"\n  Auth data: {auth_data.hex().upper()}  ({len(auth_data)} bytes)")
    print(f"  SDAD:      {sig.hex().upper()[:60]}...  ({len(sig)} bytes)")

    # Verify the SDAD structure using the ICC public key
    if icc_pk_pem:
        icc_info = verify_sdad(sig, auth_data, icc_pk_pem)
        if icc_info.get('valid'):
            print(f"\n  SDAD structure verified against ICC public key")
            print(f"  Format: 0x{icc_info.get('format', '?'):02X} (expected 0x05 for DDA SDAD)")
            if icc_info.get('icc_dynamic_number'):
                print(f"  ICC Dynamic Number: {icc_info['icc_dynamic_number'].hex().upper()}")
            if icc_info.get('hash_ok') is not None:
                print(f"  Hash check: {'OK' if icc_info['hash_ok'] else 'FAIL (hash mismatch)'}")
        else:
            print(f"  SDAD verification: {icc_info.get('error', 'unknown error')}")

    sig_b64 = base64.b64encode(sig).decode()
    result = {
        'version': '1',
        'algorithm': 'EMV-DDA-INTERNAL-AUTHENTICATE',
        'network': network,
        'auth_data': auth_data.hex(),
        'sdad': sig_b64,
        'sdad_len': len(sig),
        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
    }

    out_path = args.output or "signature.json"
    with open(out_path, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"\n  Saved to: {out_path}")


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

    algorithm = sig_bundle.get('algorithm', '')

    # EMV DDA format (from cmd_sign): verify SDAD against ICC public key
    if algorithm == 'EMV-DDA-INTERNAL-AUTHENTICATE' or 'sdad' in sig_bundle:
        sdad = base64.b64decode(sig_bundle['sdad'])
        auth_data = bytes.fromhex(sig_bundle['auth_data'])
        print(f"  Algorithm:  {algorithm}")
        print(f"  Auth data:  {auth_data.hex().upper()}  ({len(auth_data)} bytes)")
        print(f"  SDAD:       {sdad.hex().upper()[:48]}...  ({len(sdad)} bytes)")

        result = verify_sdad(sdad, auth_data, pem)

        if not result['valid']:
            print(f"\n  ✗ VERIFICATION FAILED: {result.get('error')}")
            sys.exit(1)

        hash_ok = result.get('hash_ok', False)
        idc_num = result.get('icc_dynamic_number', b'')
        idc_hex = idc_num.hex().upper() if idc_num else 'N/A'

        print(f"\n  Format byte:          0x{result['format']:02X}")
        print(f"  ICC Dynamic Number:   {idc_hex}")
        print(f"  Hash in SDAD:         {result['hash_in_sdad']}")
        print(f"  Expected hash:        {result['expected_hash']}")
        print(f"  Hash check:           {'OK' if hash_ok else 'FAIL'}")

        if hash_ok:
            print(f"\n  ✓ VERIFICATION PASSED")
        else:
            print(f"\n  ✗ VERIFICATION FAILED: hash mismatch")
            sys.exit(1)
        return

    print(f"  Unknown signature format (algorithm={algorithm!r})")
    print("  Only EMV-DDA-INTERNAL-AUTHENTICATE signatures are supported.")
    sys.exit(1)


def cmd_probe(args):
    """
    Exhaustive cryptographic APDU capability probe.

    Initialises a full EMV transaction context (SELECT → GPO → READ RECORDS)
    then systematically tests every crypto-relevant APDU and reports the
    SW status code and any response data.  Use this to discover what private-key
    operations the card actually exposes.
    """
    print("\n━━━ EMV Crypto Capability Probe ━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    conn = get_card_connection(args.reader)
    card_iface = CardInterface(conn)
    emv = EMVCard(card_iface)

    print("  Step 1: Full EMV initialisation (SELECT → GPO → READ RECORDS)...")
    if not emv.read_all(scan_all=False):
        print("  [ERROR] Failed to select application — cannot continue probe.")
        sys.exit(1)

    info = emv.get_info()
    aip = emv.data.get('82', b'')
    aip_val = (aip[0] << 8) | aip[1] if len(aip) >= 2 else 0
    print(f"  Network: {info.get('network','?')}   AID: {emv.aid.hex().upper() if emv.aid else 'N/A'}")
    print(f"  AIP: {aip.hex().upper() if aip else 'N/A'}  "
          f"SDA={'Y' if aip_val&0x4000 else 'N'} "
          f"DDA={'Y' if aip_val&0x2000 else 'N'} "
          f"CVM={'Y' if aip_val&0x1000 else 'N'} "
          f"CDA={'Y' if aip_val&0x0100 else 'N'}")
    print(f"  ATC: {emv.data.get('9F36', b'').hex().upper() or 'N/A'}")

    # Build CDOL1 data for GENERATE AC (fill with zeros for each required tag)
    cdol1 = emv.data.get('8C', b'')
    cdol2 = emv.data.get('8D', b'')
    if cdol1:
        print(f"  CDOL1: {cdol1.hex().upper()}")
    if cdol2:
        print(f"  CDOL2: {cdol2.hex().upper()}")

    def _cdol_dummy(cdol: bytes) -> bytes:
        """Build a zero-filled DOL response for probing."""
        out = b''
        i = 0
        while i < len(cdol):
            tag = cdol[i]
            if tag & 0x1F == 0x1F:
                i += 1
                tag = (tag << 8) | cdol[i]
            i += 1
            length = cdol[i]
            i += 1
            out += bytes(length)
        return out

    cdol1_data = _cdol_dummy(cdol1) if cdol1 else bytes(29)  # typical CDOL1 length
    cdol2_data = _cdol_dummy(cdol2) if cdol2 else bytes(16)

    print(f"\n  Step 2: Probing crypto APDUs...\n")
    print(f"  {'Command':<38} {'SW':>6}  Response / Notes")
    print(f"  {'─'*38} {'─'*6}  {'─'*30}")

    _SW_NAMES = {
        0x9000: "OK",
        0x6D00: "INS not supported",
        0x6A81: "Function not supported",
        0x6985: "Conditions of use not satisfied",
        0x6982: "Security status not satisfied",
        0x6984: "Referenced data not usable",
        0x6800: "CLA function not supported",
        0x6700: "Wrong length",
        0x6300: "Verification failed",
        0x63C0: "PIN try limit reached",
        0x6283: "Selected file invalid (card blocked?)",
    }

    def probe(label: str, apdu: list) -> tuple[int, bytes]:
        resp, sw1, sw2 = card_iface.send_soft(apdu)
        sw = (sw1 << 8) | sw2
        sw_name = _SW_NAMES.get(sw, _SW_NAMES.get(sw & 0xFFF0, f"SW={sw1:02X}{sw2:02X}"))
        data_str = bytes(resp).hex().upper()[:32] + ('...' if len(resp) > 16 else '') if resp else ''
        status_str = f"{sw1:02X}{sw2:02X}"
        note = f"{sw_name}" + (f"  data={data_str}" if data_str else '')
        print(f"  {label:<38} {status_str:>6}  {note}")
        return sw, bytes(resp)

    # ── RSA / ISO 7816-8 PSO operations ─────────────────────────────────────

    # PSO:DECIPHER — try with and without padding indicator byte
    enc_key_dummy = bytes(144)  # 1152-bit key = 144 bytes (matches this card's ICC key size)
    probe("PSO:DECIPHER (0x00 + 144b zeros)",
          [0x00, 0x2A, 0x80, 0x86, 0x91, 0x00] + list(enc_key_dummy) + [0x00])

    probe("PSO:DECIPHER (144b, no padding byte)",
          [0x00, 0x2A, 0x80, 0x86, 0x90] + list(enc_key_dummy) + [0x00])

    # Shorter test — some cards only accept modulus-length input
    enc_key_short = bytes(128)  # 1024-bit
    probe("PSO:DECIPHER (128b zeros)",
          [0x00, 0x2A, 0x80, 0x86, 0x81, 0x00] + list(enc_key_short) + [0x00])

    # PSO:ENCIPHER
    probe("PSO:ENCIPHER (4b test)",
          [0x00, 0x2A, 0x86, 0x80, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x00])

    # PSO:COMPUTE DIGITAL SIGNATURE (sign a pre-computed hash)
    probe("PSO:CDS (20b SHA-1 hash)",
          [0x00, 0x2A, 0x9E, 0x9A, 0x14] + [0xAA]*20 + [0x00])

    # PSO:HASH
    probe("PSO:HASH (4b data)",
          [0x00, 0x2A, 0x90, 0x80, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00])

    # PSO:VERIFY DIGITAL SIGNATURE
    probe("PSO:VERIFY DS (4b)",
          [0x00, 0x2A, 0x00, 0xA8, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x00])

    # ── Manage Security Environment ─────────────────────────────────────────

    # MSE:SET AT for internal auth / sig (key ref 0x81 = ICC private key)
    probe("MSE:SET AT sig key (B6, ref=81)",
          [0x00, 0x22, 0x41, 0xB6, 0x06, 0x84, 0x01, 0x81, 0x80, 0x01, 0x01])
    probe("PSO:CDS after MSE:B6 (20b hash)",
          [0x00, 0x2A, 0x9E, 0x9A, 0x14] + [0xBB]*20 + [0x00])

    # MSE:SET AT for decipher (key ref 0x81)
    probe("MSE:SET AT decipher (B8, ref=81)",
          [0x00, 0x22, 0x41, 0xB8, 0x06, 0x84, 0x01, 0x81, 0x80, 0x01, 0x01])
    probe("PSO:DECIPHER after MSE:B8 (0x00+144b)",
          [0x00, 0x2A, 0x80, 0x86, 0x91, 0x00] + list(enc_key_dummy) + [0x00])

    # Restore SE
    probe("MSE:RESTORE",
          [0x00, 0x22, 0xF3, 0x00, 0x00])

    # ── EMV Symmetric / GENERATE AC ────────────────────────────────────────

    # GENERATE AC — ARQC (P1=0x80 = ARQC request)
    lc = len(cdol1_data)
    probe(f"GENERATE AC ARQC (CDOL1={lc}b zeros)",
          [0x80, 0xAE, 0x80, 0x00, lc] + list(cdol1_data) + [0x00])

    # GENERATE AC — TC (P1=0x40) uses CDOL2
    lc2 = len(cdol2_data)
    probe(f"GENERATE AC TC (CDOL2={lc2}b zeros)",
          [0x80, 0xAE, 0x40, 0x00, lc2] + list(cdol2_data) + [0x00])

    # ── PIN / CVM operations ────────────────────────────────────────────────

    probe("GET CHALLENGE",
          [0x00, 0x84, 0x00, 0x00, 0x00])

    probe("VERIFY plain PIN (dummy 1234)",
          [0x00, 0x20, 0x00, 0x80, 0x08,
           0x24, 0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])

    probe("VERIFY offline enc PIN (dummy)",
          [0x00, 0x20, 0x00, 0x88, 0x08,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

    # ── GET DATA tags ───────────────────────────────────────────────────────

    get_data_tags = [
        ("9F17", "PIN Try Counter"),
        ("9F38", "PDOL"),
        ("9F49", "DDOL"),
        ("9F4F", "Log Format"),
        ("9F68", "Card Additional Processes"),
        ("9F6E", "Third Party Data"),
        ("9F08", "Application Version"),
    ]
    for tag_hex, tag_name in get_data_tags:
        tag_b = bytes.fromhex(tag_hex)
        probe(f"GET DATA {tag_hex} ({tag_name})",
              [0x00, 0xCA, tag_b[0], tag_b[1], 0x00])

    # ── INTERNAL AUTHENTICATE (should work — sanity check) ──────────────────

    probe("INTERNAL AUTHENTICATE (4b random)",
          [0x00, 0x88, 0x00, 0x00, 0x04] + list(_os.urandom(4)) + [0x00])

    print(f"\n  ─── Summary ───")
    print(f"  SW=9000 = command succeeded")
    print(f"  SW=6D00 = instruction not supported (card never implements this)")
    print(f"  SW=6A81 = function not supported")
    print(f"  SW=6985 = conditions of use not satisfied (may need different context)")
    print(f"  SW=6982 = security status not satisfied (PIN/CVM required)")
    print(f"  Run with -v to see full APDU hex for each command.")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog='emv_pki',
        description='EMV Credit Card PKI Tool — Uses chip cards as hardware security tokens.\nAll operations require a real card in the reader.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s info                               # Read card identity and cert chain
  %(prog)s raw                                # Dump all TLV tags (diagnostic)
  %(prog)s export --output card.pem           # Export ICC public key as PEM
  %(prog)s probe                              # Test all crypto APDUs the card supports
  %(prog)s encrypt --message "secret"         # Encrypt to card's ICC public key
  %(prog)s decrypt --input encrypted.json     # Decrypt via PSO:DECIPHER
  %(prog)s sign --output sig.json             # Sign via INTERNAL AUTHENTICATE (DDA)
  %(prog)s verify --signature sig.json --pubkey card.pem

Supported cards: Visa, Mastercard, Amex, Discover, JCB, UnionPay, Maestro, Interac
Hardware: Any PC/SC compliant contact reader (ACR1252U, SCM, Identive, etc.)
""")

    parser.add_argument('--reader', type=int, default=0, help='Reader index (default: 0)')
    parser.add_argument('--json', action='store_true', help='Also output raw JSON')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show raw APDUs and TLV parsing')

    sub = parser.add_subparsers(dest='command', metavar='command')

    # info
    sub.add_parser('info', help='Read card identity, AIP, and cert chain')

    # raw
    sub.add_parser('raw', help='Dump all raw TLV data from card (diagnostic)')

    # export
    p_exp = sub.add_parser('export', help='Export ICC public key as PEM (via cert chain)')
    p_exp.add_argument('--output', '-o', help='Output PEM file (default: card_pubkey.pem)')

    # probe
    sub.add_parser('probe', help='Exhaustive crypto APDU capability probe (with full EMV context)')

    # encrypt
    p_enc = sub.add_parser('encrypt', help='Encrypt data to card ICC public key (RSA-OAEP hybrid)')
    p_enc.add_argument('--input', '-i', help='Input file to encrypt')
    p_enc.add_argument('--message', '-m', help='Message string to encrypt')
    p_enc.add_argument('--output', '-o', help='Output JSON bundle (default: encrypted.json)')

    # decrypt
    p_dec = sub.add_parser('decrypt', help='Decrypt data using card PSO:DECIPHER')
    p_dec.add_argument('--input', '-i', required=True, help='Encrypted JSON bundle')
    p_dec.add_argument('--output', '-o', help='Output decrypted file (default: stdout)')

    # sign
    p_sign = sub.add_parser('sign', help='Sign via INTERNAL AUTHENTICATE (DDA)')
    p_sign.add_argument('--output', '-o', help='Output signature JSON (default: signature.json)')

    # verify
    p_ver = sub.add_parser('verify', help='Verify an SDAD signature from sign command')
    p_ver.add_argument('--signature', '-s', required=True, help='Signature JSON file')
    p_ver.add_argument('--pubkey', '-k', required=True, help='Card public key PEM')

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
        'probe':   cmd_probe,
        'encrypt': cmd_encrypt,
        'decrypt': cmd_decrypt,
        'sign':    cmd_sign,
        'verify':  cmd_verify,
    }

    dispatch[args.command](args)


if __name__ == '__main__':
    main()

