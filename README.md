# back-stop

A single-file browser tool for storing account recovery codes: the one-time
codes a provider hands you to get back in when your authenticator is gone. It
holds them encrypted, exports an encrypted file, and prints a QR backup and a
key card for offline storage.

![screenshot](docs/screenshot.png)

Open `index.html`. No build step, no dependencies, no network calls.

    index.html    the tool. One file, open it in a browser.
    recover.py    offline decryption without the browser. Standard library only.
    README.md     this file.
    LICENSE       MIT.
    _headers      security headers for Netlify-style hosting.
    .htaccess     the same for Apache.

## What it does

- Create a vault behind a passphrase, add accounts, paste in blocks of codes.
- Export an encrypted `.json` file. Re-open it, add more, export again.
- Print every code in the clear, three dense columns to a sheet, for a safe.
- Print an encrypted QR backup for somewhere less trusted.
- Print a key card carrying the raw data key, as a break-glass path if the
  passphrase is ever lost.
- Restore from either the exported file or the printed QR codes.

## Crypto

Envelope encryption. The vault body is AES-256-GCM under a random 256-bit data
key. That data key is wrapped with a second AES-256-GCM key derived from the
passphrase with PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt.
Both the wrapped key and the body go in the exported file. The additional
authenticated data for both is the ASCII string `back-stop-vault-1`.

The data key stays stable across exports, so a printed key card keeps working
as the vault grows. Rotating it invalidates every card already printed, which
is why it is an explicit action rather than a side effect.

### Key card text form

The card is read by eye and retyped more often than it is scanned, so the key
is printed in Crockford base32, not base64: one case, and the letters `I`, `L`,
`O` and `U` never appear. On input `I` and `L` fold to `1` and `O` folds to `0`,
so the classic paper misreads cost nothing. Spaces, line breaks and case are
ignored.

Layout is 52 characters of key followed by 2 check characters, the first two
Crockford digits of `SHA-256(key)`. Ten bits of check, so a single-character
slip is reported as a typo rather than failing as an opaque wrong key. The card
also carries the same string as a QR symbol, so it can be scanned and pasted
instead of transcribed.

Changing the last of the 52 characters can leave the key unchanged: 52 base32
characters carry 260 bits and the key is 256, so the final character has 4 bits
of padding. Both forms decode to the same key and both unlock.

### Exported file

```json
{
  "app": "back-stop", "format": "back-stop-vault-1", "schema": 1,
  "kdf":  { "alg": "PBKDF2-SHA256", "iter": 600000, "salt": "base64" },
  "wrap": { "alg": "A256GCM", "iv": "base64", "ct": "base64" },
  "body": { "alg": "A256GCM", "comp": "gzip", "iv": "base64", "ct": "base64" }
}
```

### Paper envelope

The QR codes carry a binary envelope, not the JSON, because base64 of JSON of
base64 wastes about a third of each symbol. Lengths in bytes:

| Field | Bytes |
|---|---|
| magic `BS` | 2 |
| envelope version | 1 |
| PBKDF2 iterations / 1000, big endian | 2 |
| PBKDF2 salt | 16 |
| wrapped-key nonce | 12 |
| wrapped 32-byte data key + 16-byte tag | 48 |
| body nonce | 12 |
| flags, bit 0 set when the body is gzipped | 1 |
| body ciphertext + tag | rest |

Base64 of that, split across symbols, each prefixed `BS1:i/n:`. Concatenate in
index order before decoding. This layout is also printed on the backup page, so
the codes can be decrypted with a short script and no browser.

Roughly sixty codes fit in one symbol. Symbols are capped at version 25 so the
printed modules stay large enough to scan; larger vaults get more pages.

## Three backups, three jobs

| | Needs at recovery time | Where it lives |
|---|---|---|
| Encrypted `.json` | this tool + passphrase | disk, sync, wherever |
| Encrypted QR sheet | a scanner + passphrase or key card | a folder, a deposit box, a relative's house |
| Plaintext sheet | nothing | a safe |

The plaintext sheet is the strongest last resort precisely because it depends on
nothing: no passphrase, no scanner, no working copy of this tool, and no faith
in the QR encoder being correct. It is also the one that is equivalent to the
codes themselves, so it needs physical protection rather than cryptographic.
Keep it apart from the QR sheet and the key card.

### Paper only is a complete workflow

Nothing requires you to keep a `.json` file. Print a QR backup and a key card,
store them apart, and that is a whole strategy: **From paper** on the start
panel takes the scanned text back in, and either the passphrase or the key card
opens it. The encrypted file is a convenience, not a dependency.

### Lock versus close

**Lock** re-seals the current state into an envelope held in this tab and drops
the keys, so the passphrase or the key card reopens it without re-reading a file
or re-scanning paper. It re-seals rather than keeping the envelope it opened
from, because that one goes stale as soon as an account is edited and reopening
it would silently roll the vault back. The idle timer locks the same way.

**Close** discards the envelope too. Nothing is written to the browser either
way, so export or print before closing the tab.

Restoring from the QR sheet uses your phone's camera app to decode the symbols
to text, which you paste into "Restore from paper". There is no scanner in the
tool itself, only the reassembler, so this is a one-device flow on a phone and
awkward on a desktop.

## recover.py

The other half of the paper strategy. A backup you can only read with the tool
that wrote it is a bet that the tool still exists, still runs, and still works
in whatever browser you have in ten years. `recover.py` removes that bet: it
decrypts a vault file or a printed backup and prints the codes.

    python3 recover.py vault.json            # passphrase, prompted
    python3 recover.py scanned.txt           # text scanned off the QR sheet
    python3 recover.py vault.json --key      # recovery key card instead
    python3 recover.py vault.json --json     # raw JSON rather than a listing
    pbpaste | python3 recover.py             # straight from a scan

Python 3.6 or newer, and nothing else. It runs under `python3 -S`, with
site-packages disabled, which is the check that it really has no dependencies.

It takes all three input forms and works out which it has: the exported
`.json`, the `BS1:` chunks scanned off the printed sheet in any order, or a
bare base64 envelope. Either credential opens it - the passphrase, or the 54
characters off the key card, with the same tolerance the tool has for case,
spacing and reading `O` for `0` or `I` for `1`.

### Why there are no dependencies

A recovery tool you cannot run until you have installed something is not a
recovery tool. The machine where you need this may be offline, locked down,
borrowed, or simply newer than whatever `pip` wanted to fetch. So the script
imports nothing outside the standard library.

PBKDF2, gzip, base64 and JSON are all stdlib. AES-256-GCM is not, so it is
implemented in the file - around 150 lines of AES-256 plus GHASH and counter
mode. Decryption only: GCM needs no inverse cipher, and a tool that cannot
encrypt cannot damage a vault. The tag is checked before any plaintext is
released, with a constant-time compare.

### Verify it before you trust it

Hand-written crypto deserves suspicion, so the script carries its own
known-answer tests:

    python3 recover.py --selftest

That runs the AES-256 block vector from FIPS-197 C.3, GCM cases 13, 14 and 16
from the NIST test set that accompanies SP 800-38D, a deliberately corrupted
tag that must be rejected, a PBKDF2-HMAC-SHA256 vector, and the key card
encoding round-tripped including the misread-letter and typo cases. All ten
pass on a good copy. If any fail, the copy is damaged or modified and should
not be used.

It has also been checked end to end against real output from `index.html`:
vault files and paper chunks generated in a browser, printed to A4, rasterised
at 300 dpi, decoded from the pixels with `zbar`, and opened by `recover.py`
with both the passphrase and the key card. The codes came back byte-identical.

### What it deliberately does not do

It only reads. There is no edit, no re-encrypt, no export. Recovery is a
read-only problem, and a break-glass tool with write paths is a break-glass
tool that can destroy the thing it was meant to rescue.

Output goes to stdout, and when that is redirected the script says on stderr
that the result is now plaintext outside any encryption. It will not write a
file for you.



## What leaks, and what does not

- **No localStorage.** Codes are never written to the browser. Plaintext lives
  in the tab's memory and nowhere else; closing the tab discards anything not
  exported. Only the three appearance settings are stored.
- **No network.** The content security policy in the head of the file sets
  `default-src 'none'` and `connect-src 'none'`.
- Code fields are blurred on screen, with hold-to-show per account, and re-blur
  on tab switch or window blur. A field with keyboard focus stays legible,
  because a blurred field cannot be typed into.
- Code fields are removed from every print path unconditionally. A CSS blur is
  cosmetic: the characters would stay selectable in a PDF. The plaintext sheet
  renders into its own block rather than unhiding those fields, so an
  accidental Ctrl+P can never carry codes even with a vault open.
- Printing in the clear asks for confirmation and names the consequence.
- `autocomplete`, `autocapitalize` and `spellcheck` are off everywhere. Some
  browsers send spellcheck text to a remote service.
- No copy buttons. Clipboard history syncs on Windows.
- The vault auto-locks after five minutes idle, and closing the tab with a
  vault open prompts first.

Print to paper on a local printer. Print-to-PDF writes to disk and a network
printer hands the job to a spooler; check the queue afterwards.

## Printing

Only three actions print: **Print key card**, **Print backup** and **Print in
the clear**. An accidental Ctrl+P prints a short notice and nothing else, which
matters because the shared template's print stylesheet deliberately unhides
every tab to print a whole document - here that would have put the About text
and the account inventory, providers and usernames, on a page nobody meant to
produce. Codes themselves were never reachable that way: the code fields are
removed from the print output outright rather than blurred, since a CSS blur
leaves the characters selectable in a PDF text layer.

## Known limits

- PBKDF2 is GPU-friendly and the browser offers nothing stronger without a
  dependency, so a short passphrase will not survive an offline attack on the
  exported file. Six or more unrelated words.
- The AES-GCM in `recover.py` is hand-written rather than an audited 
  third-party library. It passesthe NIST vectors and agrees with WebCrypto 
  on real vaults, which is evidencebut not a review. It is a fallback for when 
  the browser is gone, not the everyday path.
- Ten check bits will not catch every transcription error. A slip that passes
  the check still fails at the decrypt, with the generic message.
- The key card decrypts the vault on its own. Store it apart from both the
  vault file and the printed QR backup, or the encryption buys nothing.
- Hosting this file anywhere means whoever controls that origin controls the
  code that touches your plaintext. Verify the hash of a hosted copy against
  your local one before entering real codes.

## Licence

MIT, Shane McElhinney.
