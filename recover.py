#!/usr/bin/env python3
"""
recover.py - read a back-stop vault without back-stop.

back-stop stores account recovery codes encrypted in a browser tab. This script
is the break-glass path for the day that tab is not available: no browser, no
network, no pip. It reads either an exported vault file or the text scanned off
a printed paper backup, and prints the codes.

Standard library only, by design. A recovery tool you cannot run until you have
installed something is not a recovery tool, so AES-256-GCM is implemented here
rather than imported. Everything else - PBKDF2, gzip, base64, JSON - is stdlib
already. Verify the crypto before trusting it:

    python3 recover.py --selftest

Usage:

    python3 recover.py vault.json                  # passphrase, prompted
    python3 recover.py backup.txt                  # scanned QR text
    python3 recover.py vault.json --key            # recovery key card instead
    python3 recover.py vault.json --json           # emit JSON, not a listing
    python3 recover.py --selftest                  # NIST vectors, then exit

Reads stdin when no file is given, so a scan can be piped straight in:

    pbpaste | python3 recover.py

Output goes to stdout. It is plaintext recovery codes, so redirecting it to a
file writes your codes to disk unencrypted; the script says so and will not do
it for you.

MIT licensed, same as back-stop. Shane McElhinney.
"""

import argparse
import base64
import binascii
import getpass
import gzip
import hashlib
import hmac
import json
import re
import sys

FORMAT = b"back-stop-vault-1"   # AAD for both GCM layers
ENV_MAGIC = b"BS"
ENV_VER = 1
ENV_FIXED = 3 + 2 + 16 + 12 + 48 + 12 + 1


# ---------------------------------------------------------------- AES-256

_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d]


def _xtime(a):
    """Multiply by x in GF(2^8), reducing by the AES polynomial."""
    a <<= 1
    return (a ^ 0x1b) & 0xff if a & 0x100 else a


class AES:
    """AES-256 block encryption. Encryption only: GCM needs no inverse cipher,
    since both its counter mode and its GHASH use the forward direction."""

    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("AES-256 needs a 32 byte key, got %d" % len(key))
        self.rounds = 14
        nk = 8
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (self.rounds + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = t[1:] + t[:1]
                t = [_SBOX[b] for b in t]
                t[0] ^= _RCON[i // nk - 1]
            elif i % nk == 4:
                t = [_SBOX[b] for b in t]
            w.append([w[i - nk][j] ^ t[j] for j in range(4)])
        # round keys as flat 16-byte lists, column-major as the state is
        self.rk = [sum(w[4 * r:4 * r + 4], []) for r in range(self.rounds + 1)]

    def encrypt_block(self, block):
        s = [block[i] ^ self.rk[0][i] for i in range(16)]
        for r in range(1, self.rounds + 1):
            s = [_SBOX[b] for b in s]
            # ShiftRows, on a column-major state
            s = [
                s[0], s[5], s[10], s[15],
                s[4], s[9], s[14], s[3],
                s[8], s[13], s[2], s[7],
                s[12], s[1], s[6], s[11],
            ]
            if r != self.rounds:
                t = []
                for c in range(4):
                    a = s[4 * c:4 * c + 4]
                    t += [
                        _xtime(a[0]) ^ (_xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3],
                        a[0] ^ _xtime(a[1]) ^ (_xtime(a[2]) ^ a[2]) ^ a[3],
                        a[0] ^ a[1] ^ _xtime(a[2]) ^ (_xtime(a[3]) ^ a[3]),
                        (_xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ _xtime(a[3]),
                    ]
                s = t
            s = [s[i] ^ self.rk[r][i] for i in range(16)]
        return bytes(s)


# ---------------------------------------------------------------- GCM

def _ghash(h_key, data):
    """GHASH over 128-bit blocks, carry-less multiply in GF(2^128)."""
    h = int.from_bytes(h_key, "big")
    y = 0
    for i in range(0, len(data), 16):
        block = data[i:i + 16].ljust(16, b"\0")
        y ^= int.from_bytes(block, "big")
        # multiply y by h
        z = 0
        v = y
        for bit in range(127, -1, -1):
            if (h >> bit) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ 0xe1 << 120
            else:
                v >>= 1
        y = z
    return y.to_bytes(16, "big")


def _gctr(aes, icb, data):
    out = bytearray()
    ctr = int.from_bytes(icb, "big")
    for i in range(0, len(data), 16):
        ks = aes.encrypt_block(ctr.to_bytes(16, "big"))
        chunk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        ctr = (ctr & ~0xffffffff) | ((ctr + 1) & 0xffffffff)
    return bytes(out)


def aes_gcm_decrypt(key, nonce, ciphertext_and_tag, aad=b""):
    """AES-256-GCM open. ciphertext_and_tag is the ciphertext with its 16 byte
    tag appended, which is how WebCrypto emits it. Raises on a bad tag."""
    if len(nonce) != 12:
        raise ValueError("expected a 12 byte nonce, got %d" % len(nonce))
    if len(ciphertext_and_tag) < 16:
        raise ValueError("ciphertext is too short to hold a tag")
    ct, tag = ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]

    aes = AES(key)
    h = aes.encrypt_block(b"\0" * 16)
    j0 = nonce + b"\x00\x00\x00\x01"

    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
    pad = lambda b: b + b"\0" * (-len(b) % 16)
    expect = _ghash(h, pad(aad) + pad(ct) + lengths)
    expect = bytes(a ^ b for a, b in zip(expect, aes.encrypt_block(j0)))

    # Compare before decrypting, and in constant time: a tag mismatch means
    # the input is not authentic and the plaintext must not be released.
    if not hmac.compare_digest(expect, tag):
        raise ValueError("authentication failed")

    icb = j0[:12] + (2).to_bytes(4, "big")
    return _gctr(aes, icb, ct)


# ---------------------------------------------------------------- key card

C32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def parse_key(text):
    """Decode a printed recovery key. Crockford base32: one case, no I L O U,
    with I and L read back as 1 and O as 0, then two check characters."""
    s = text.strip()
    s = re.sub(r"^BSK1:", "", s, flags=re.I)
    c = re.sub(r"[^0-9A-Z]", "", s.upper())
    c = c.replace("I", "1").replace("L", "1").replace("O", "0")

    if re.search(r"[+/=]", s) or len(c) in (43, 44):
        raw = base64.b64decode(re.sub(r"\s+", "", s) + "===")   # 0.9.0 card
    elif len(c) in (52, 54):
        acc = bits = 0
        out = bytearray()
        for ch in c[:52]:
            acc = (acc << 5) | C32.index(ch)
            bits += 5
            if bits >= 8:
                bits -= 8
                out.append((acc >> bits) & 0xff)
        raw = bytes(out)
        if len(c) == 54:
            h = hashlib.sha256(raw).digest()
            if C32[h[0] & 31] + C32[h[1] & 31] != c[52:]:
                raise ValueError(
                    "that key has a typo in it, check it against the card a character at a time")
    else:
        raise ValueError("a recovery key is 54 characters, that one has %d" % len(c))

    if len(raw) != 32:
        raise ValueError("a recovery key is 32 bytes, that one decodes to %d" % len(raw))
    return raw


# ---------------------------------------------------------------- envelopes

def unpack_paper(text):
    """Reassemble the chunks scanned off a printed backup. Any order, and any
    surrounding noise a scanner or a notes app may have added."""
    found = {}
    total = None
    for m in re.finditer(r"BS1:(\d+)/(\d+):([A-Za-z0-9+/=]+)", text):
        i, n, payload = int(m.group(1)), int(m.group(2)), m.group(3)
        if total is None:
            total = n
        elif total != n:
            raise ValueError("these chunks are from different backups (%d and %d)" % (total, n))
        found[i] = payload
    if total is None:
        raise ValueError("no back-stop chunks found in that text (expected BS1:1/n:...)")
    missing = [i for i in range(1, total + 1) if i not in found]
    if missing:
        raise ValueError("missing chunk %s of %d" % (", ".join(map(str, missing)), total))
    joined = "".join(found[i] for i in range(1, total + 1))
    return base64.b64decode(joined + "=" * (-len(joined) % 4))


def parse_envelope(b):
    """The compact binary form printed as QR. Layout is on the printed page."""
    if len(b) <= ENV_FIXED:
        raise ValueError("that backup is truncated")
    if b[0:2] != ENV_MAGIC:
        raise ValueError("that is not a back-stop backup")
    if b[2] != ENV_VER:
        raise ValueError("that backup was written by a newer version of back-stop")
    o = 3
    iterations = int.from_bytes(b[o:o + 2], "big") * 1000
    o += 2
    salt, o = b[o:o + 16], o + 16
    wrap_iv, o = b[o:o + 12], o + 12
    wrap_ct, o = b[o:o + 48], o + 48
    body_iv, o = b[o:o + 12], o + 12
    flags, o = b[o], o + 1
    return {
        "iterations": iterations,
        "salt": salt,
        "wrap_iv": wrap_iv,
        "wrap_ct": wrap_ct,
        "body_iv": body_iv,
        "gzip": bool(flags & 1),
        "body_ct": b[o:],
    }


def parse_vault_file(text):
    """The exported .json form. Same fields, base64 in a JSON wrapper."""
    d = json.loads(text)
    if d.get("format") and d["format"] != FORMAT.decode():
        raise ValueError("unexpected vault format %r" % d["format"])
    b64 = lambda s: base64.b64decode(s)
    return {
        "iterations": d["kdf"]["iter"],
        "salt": b64(d["kdf"]["salt"]),
        "wrap_iv": b64(d["wrap"]["iv"]),
        "wrap_ct": b64(d["wrap"]["ct"]),
        "body_iv": b64(d["body"]["iv"]),
        "gzip": d["body"].get("comp") == "gzip",
        "body_ct": b64(d["body"]["ct"]),
    }


def load(text):
    """Accept whichever of the three forms was handed to us."""
    stripped = text.strip()
    if stripped.startswith("{"):
        return parse_vault_file(stripped)
    if "BS1:" in stripped:
        return parse_envelope(unpack_paper(stripped))
    # a bare base64 envelope, e.g. one chunk with its prefix already removed
    try:
        raw = base64.b64decode(re.sub(r"\s+", "", stripped) + "==", validate=False)
    except (binascii.Error, ValueError):
        raise ValueError("could not tell what that input is")
    return parse_envelope(raw)


# ---------------------------------------------------------------- unwrap

def open_vault(env, passphrase=None, data_key=None):
    """Unwrap the data key, then open the body. The data key is random and
    per-vault; the passphrase only ever protects the wrapper, which is why the
    printed card - the data key itself - opens the vault on its own."""
    if data_key is None:
        if passphrase is None:
            raise ValueError("need a passphrase or a recovery key")
        wrap_key = hashlib.pbkdf2_hmac(
            "sha256", passphrase.encode("utf-8"), env["salt"], env["iterations"], 32)
        try:
            data_key = aes_gcm_decrypt(wrap_key, env["wrap_iv"], env["wrap_ct"], FORMAT)
        except ValueError:
            raise ValueError("that passphrase does not open this vault")
        if len(data_key) != 32:
            raise ValueError("unwrapped key is %d bytes, expected 32" % len(data_key))

    try:
        body = aes_gcm_decrypt(data_key, env["body_iv"], env["body_ct"], FORMAT)
    except ValueError:
        raise ValueError("that key does not open this vault, or the backup is damaged")

    if env["gzip"]:
        body = gzip.decompress(body)
    return json.loads(body.decode("utf-8"))


# ---------------------------------------------------------------- output

def render(vault):
    items = vault.get("items", [])
    meta = vault.get("meta", {})
    lines = []
    label = meta.get("label") or "(unlabelled)"
    total = sum(len([c for c in (i.get("codes") or "").splitlines() if c.strip()]) for i in items)
    lines.append("back-stop vault: %s" % label)
    lines.append("%d account%s, %d code%s"
                 % (len(items), "" if len(items) == 1 else "s",
                    total, "" if total == 1 else "s"))
    lines.append("")
    for i in items:
        head = i.get("site") or "(unnamed)"
        if i.get("user"):
            head += "  -  " + i["user"]
        lines.append(head)
        if i.get("note"):
            lines.append("  note: " + i["note"])
        for c in (i.get("codes") or "").splitlines():
            if c.strip():
                lines.append("  " + c.strip())
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------- selftest

def selftest():
    """Known-answer tests before you trust this with a real vault. The GCM
    vectors are from the NIST submission that accompanies SP 800-38D."""
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print("  %-42s %s" % (name, "pass" if good else "FAIL"))
        if not good:
            print("     got  %r\n     want %r" % (got, want))

    h = lambda s: bytes.fromhex(s)

    # FIPS-197 C.3: AES-256 single block
    check("AES-256 block (FIPS-197 C.3)",
          AES(h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
          .encrypt_block(h("00112233445566778899aabbccddeeff")),
          h("8ea2b7ca516745bfeafc49904b496089"))

    # GCM test case 13: 256-bit key, empty plaintext and AAD
    check("GCM case 13 (empty, tag only)",
          aes_gcm_decrypt(h("00" * 32), h("00" * 12), h("530f8afbc74536b9a963b4f1c4cb738b")),
          b"")

    # GCM test case 14: 256-bit key, one zero block
    check("GCM case 14 (one block)",
          aes_gcm_decrypt(h("00" * 32), h("00" * 12),
                          h("cea7403d4d606b6e074ec5d3baf39d18"
                            "d0d1c8a799996bf0265b98b5d48ab919")),
          h("00" * 16))

    # GCM test case 16: 256-bit key, with AAD, multi-block
    check("GCM case 16 (AAD, multi-block)",
          aes_gcm_decrypt(
              h("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
              h("cafebabefacedbaddecaf888"),
              h("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
                "76fc6ece0f4e1768cddf8853bb2d551b"),
              h("feedfacedeadbeeffeedfacedeadbeefabaddad2")),
          h("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"))

    # a tampered tag must be rejected
    try:
        aes_gcm_decrypt(h("00" * 32), h("00" * 12), h("00" * 32))
        check("tampered tag rejected", "accepted", "rejected")
    except ValueError:
        check("tampered tag rejected", "rejected", "rejected")

    # PBKDF2 against RFC 6070 vector 1, adapted to SHA-256
    check("PBKDF2-HMAC-SHA256 (RFC 6070 salt)",
          hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1, 32),
          h("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"))

    # the key card encoding, round-tripped
    key = bytes(range(32))
    acc = bits = 0
    enc = ""
    for b in key:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            enc += C32[(acc >> bits) & 31]
    if bits:
        enc += C32[(acc << (5 - bits)) & 31]
    digest = hashlib.sha256(key).digest()
    card = enc + C32[digest[0] & 31] + C32[digest[1] & 31]
    check("recovery key decode", parse_key(card), key)
    check("recovery key, spaced and lowercase",
          parse_key(" ".join(card[i:i + 4] for i in range(0, len(card), 4)).lower()), key)
    check("recovery key, O for 0 and I for 1",
          parse_key(card.replace("0", "O").replace("1", "I")), key)
    try:
        bad = card[:10] + ("2" if card[10] != "2" else "3") + card[11:]
        parse_key(bad)
        check("recovery key typo reported", "accepted", "rejected")
    except ValueError as e:
        check("recovery key typo reported", "typo" in str(e), True)

    print("\n%s" % ("all checks passed" if ok else "SOME CHECKS FAILED - do not trust this copy"))
    return 0 if ok else 1


# ---------------------------------------------------------------- cli

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Read a back-stop vault offline. Standard library only.",
        epilog="Output is plaintext recovery codes. Prefer reading it on screen "
               "over redirecting it to a file.")
    ap.add_argument("file", nargs="?",
                    help="vault .json, or a text file of scanned QR chunks. "
                         "Reads stdin when omitted.")
    ap.add_argument("--key", action="store_true",
                    help="unlock with the printed recovery key card instead of a passphrase")
    ap.add_argument("--json", action="store_true", dest="as_json",
                    help="emit the decrypted vault as JSON rather than a listing")
    ap.add_argument("--selftest", action="store_true",
                    help="run known-answer tests on the bundled crypto and exit")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        if sys.stdin.isatty():
            print("Paste the vault file or the scanned backup text, then Ctrl-D:",
                  file=sys.stderr)
        text = sys.stdin.read()

    if not text.strip():
        print("recover.py: nothing to read", file=sys.stderr)
        return 2

    try:
        env = load(text)
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        print("recover.py: %s" % e, file=sys.stderr)
        return 2

    try:
        if args.key:
            entered = getpass.getpass("Recovery key from the printed card: ")
            vault = open_vault(env, data_key=parse_key(entered))
        else:
            vault = open_vault(env, passphrase=getpass.getpass("Passphrase: "))
    except ValueError as e:
        print("recover.py: %s" % e, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130

    out = json.dumps(vault, indent=2) + "\n" if args.as_json else render(vault)
    sys.stdout.write(out)
    if not sys.stdout.isatty():
        print("recover.py: that output is plaintext recovery codes, now outside "
              "any encryption. Delete it when you are done.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
