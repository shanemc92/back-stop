# Reviewing back-stop

This is a guide for reviewing back-stop, by a person or by an AI assistant. It
says what the tool claims, where in the code each claim lives, and which parts
deserve the most suspicion. It is a map, not a verdict: nothing in it has been
independently audited, and the README says so.

To use it with an assistant, give the assistant this repository and ask it to
follow this file. Ask it to quote the code it relied on for each finding, and
to say plainly what it could not check.

## Scope

In scope: `index.html` (the tool, one file, no dependencies) and `recover.py`
(the standalone reader, Python standard library only).

Out of scope: the browser, its Web Crypto implementation, the operating system,
the printer, and the hosting of any copy you did not make yourself.

Everything is hand-written except what the browser and the Python standard
library provide. There is no build step, no package manager and no vendored
code, so what is in the repository is what runs.

## Read first

The README sections **Privacy**, **What it protects against, and what it does
not**, **Known limits** and **Technical reference**. They are the claims. The
job is to find where the code does not live up to them.

Do not report as new anything those sections already admit.

## Claims, and where to check each

Names are functions or constants in `index.html` unless marked `recover.py`.
Line numbers are left out on purpose: they drift, names do not.

| # | Claim | Check | A pass looks like |
|---|---|---|---|
| 1 | It makes no network connection | The CSP `<meta>` in `<head>`, plus `_headers` and `.htaccess`. Search for `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`, `import(`, `Worker`, `serviceWorker`, `window.open`, `location`, and any `src` or `href` that is not a `data:` or `blob:` URL | No hits that reach out, and a policy of `default-src 'none'` with `connect-src 'none'` |
| 2 | Nothing is stored in the browser except design, mode and accent | The `store` object and every caller. `persist()` is meant to be empty and `restore()` only deletes | `localStorage` is touched only for the keys `design`, `mode` and `accent`. No `sessionStorage`, `indexedDB` or cookies |
| 3 | Keys, salts and nonces are random | `rnd`, `createVault`, `rekey`, `gcmEnc`. Search for `Math.random` | Every secret value comes from `crypto.getRandomValues`, a fresh 12-byte nonce for every encryption, a 16-byte salt, a 32-byte data key |
| 4 | The vault is AES-256-GCM under a random data key, wrapped by a PBKDF2 key | `deriveWrapKey`, `gcmEnc`, `gcmDec`, `ITER`, `FORMAT`, `aad` | PBKDF2-HMAC-SHA256, 600,000 rounds, NFKC-normalised passphrase, and the same `FORMAT` string as additional authenticated data on both layers |
| 5 | A hostile file cannot hang or weaken the tool | `checkIter`, `MAX_FILE_BYTES`, `loadJson`, `qrJoin`, `envParse` | Iteration counts bounded both ways, file size capped before parsing, every length and magic number checked before use |
| 6 | A damaged or altered copy fails to open instead of giving wrong codes | `gcmDec`, `openWithPass`, `openWithKey`, `adopt`, `inflate` | Decryption errors are never swallowed, and decompression only ever sees data that has already authenticated |
| 7 | The key card is the data key and nothing else | `b32`, `unb32`, `keyCheck`, `keyString`, `parseKey` | A round trip is exact. The two check characters are a typo detector only: the decrypt is the real authentication. Folding of `I`, `L` and `O` cannot map two different keys to one string |
| 8 | The printed backup carries the same envelope as the file | `envBuild`, `envParse`, `qrChunks`, `qrJoin`, and `parse_envelope`, `unpack_paper` in `recover.py` | The byte layout in the README, the printed note and both parsers agree. Chunks from two backups are refused, and so is an incomplete set |
| 9 | The QR codes are correct | `qrEncode`, `qrCodewords`, `qrSkeleton`, `qrPlace`, `qrPenalty`, `qrFormatBits`, `qrVersionBits`, and the tables `QR_ECC`, `QR_CAP`, `QR_ALIGN` | See the next section. This is hand-written and the part most likely to hide a quiet bug |
| 10 | `recover.py` is correct without a library | `AES`, `aes_gcm_decrypt`, `_ghash`, `_gctr`, `open_vault`, `selftest` | Known-answer tests pass, the tag compare uses `hmac.compare_digest`, and a vault written by the page opens |
| 11 | `recover.py` and the page agree | `parse_key` against `parseKey`, `_sort_key` against `sortItems`, `open_vault` against `openWithPass` | The same input gives the same result, including accented passphrases and the key card typed badly |
| 12 | Codes stay off screen, paper and the clipboard unless asked | The `blurred` class, `reblurAll`, the `visibilitychange` and `blur` listeners, the print block at the end of the `<style>`, and a search for `clipboard` and `execCommand` | No copy button, no clipboard write, code fields removed from every print path but the plaintext sheet, and an accidental Ctrl+P prints only a notice |
| 13 | Only the three print buttons print | `printCard`, `printBackup`, `printPlain`, the `data-print` attribute, and the `@media print` rules that depend on it | Every path sets `data-print`, removes it again on `afterprint`, and clears what it put in the DOM |
| 14 | Lock, Close and idle-lock clear the vault | `lockVault`, `closeVault`, `wipe`, `bumpIdle`, `IDLE_MS` | Key bytes zeroed, references dropped, form fields cleared, timer reset on activity |
| 15 | Untrusted text never becomes markup | Search for `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function` | No hits. File contents, scanned text and account names reach the page through `textContent` or `value` only |
| 16 | The scanner stores and sends nothing it reads | The `SCAN` module, and the searches for claims 1, 2 and 12 | `SCAN` never touches `store`, `localStorage`, a URL or a form, and nothing in the page writes to the clipboard. What it reads lives in its own variables and is cleared by `reset`, the idle timer, and `render` once the vault is open |
| 17 | The camera is on only while asked for | `startCamera`, `stopCamera`, `deliver`, `unlockWithKey` (each stops it), the `visibilitychange` and `pagehide` listeners, and `Permissions-Policy` in `_headers` and `.htaccess` | Every path that ends a scan stops the tracks. Only the Scan with the camera and Scan key card buttons, and the camera picker, start it. The policy is `camera=(self)`, which covers the whole page, so the page's own restraint is what is being checked |
| 18 | The decoder only reports codes whose error correction checks out | `QRD.decode`, `readWithMask`, `rsCorrect`, `decodeModules` | Every block must correct and re-check to zero syndromes before a code is returned. A code that is not byte mode at level M is refused. A mirror image is read by `transposed`. See the next section |
| 19 | What the scanner hands over is exactly the backup, and nothing else | `take`, `takeSheet`, `checkJoined`, `joinedText`, `deliver` | Only `BS1:i/n:` lines of the base64 alphabet are kept. Sheets from two prints, a repeated sheet that differs, and a joined result that is not a back-stop envelope are refused. Unknown codes are never displayed. With the camera on for the key card, sheets are ignored, so they cannot replace an open vault |
| 20 | A scanned key is checked, never shown and never copied | `keyFrom`, `unlockWithKey`, `unlockWithKeyText` | `keyFrom` goes through `parseKey`, and the key is passed to `unlockWithKeyText`, the function the typed key uses, without being written to `#inKey` or anywhere on screen. The scanner's copy is dropped as it is used |
| 21 | The scanner reaches the vault only through the front door | `loadPaper`, `deliver`, `unlockWithKeyText`, `offerKey` | `loadPaper` is the one function pasted text and the scanner share. The scanner reads `vault.open` and `pending` and nothing else of the vault: no `state`, no `vault.rawKey`, no `vault.dataKey` |

## The hand-written parts

Two things here are normally a library, and each deserves more suspicion than
the rest put together.

**The QR encoder.** A wrong table entry would not crash anything. It would
produce a symbol that scans on some phones and not others, or one that scans
but carries damaged data that decryption then rejects, and the owner would not
find out until the day they needed the paper. To check it:

1. Generate backups of many different sizes so that every version from 1 to
   `QR_MAX_VERSION` is produced, including the sizes either side of each
   version boundary and every multi-sheet split.
2. Decode each symbol with an independent reader, not one written by the same
   hand: ZXing, ZBar or OpenCV are all fine.
3. Join the chunks, run them through `recover.py`, and compare the codes with
   what went in.
4. Compare `QR_ECC`, `QR_CAP` and `QR_ALIGN` entry by entry with ISO/IEC
   18004, and the generator polynomial arithmetic (`GF_EXP`, `GF_LOG`, `rsGen`,
   `rsEc`, polynomial `0x11d`) with the standard.

**The QR decoder (`QRD`).** Written by hand so there is nothing third party in
the page, and so held to the same standard as the encoder. Two kinds of failure
matter: one that makes it miss a code that is there, which is a nuisance, and
one that makes it return text that is not what is printed, which is the one to
look for. Reed-Solomon makes the second unlikely, but a decoder that shares a
mistake with the encoder would agree with it, so check against something that
does not:

1. Take the encoder, `qrEncode`, and encode payloads of every length it
   accepts, from 1 byte up to the version 40 limit. Decode each with
   `QRD.decode` and with an independent reader, and compare the text, and the
   version, with what went in.
2. Flip random data modules, up to the error correction limit, and confirm the
   text still comes back, and that going well beyond the limit gives a miss and
   never different text.
3. Mirror and rotate symbols through all eight orientations, and confirm each
   reads and that `mirrored` is set only for the four reflections.
4. Print backups and key cards from the page to PDF, render the pages at a
   range of resolutions and decode them, as a user's photo or screenshot would
   be, and compare with the independent reader's result.
5. Photograph or simulate photographing printed sheets with tilt, blur, noise
   and uneven light, at the resolutions of a webcam and a phone, and confirm the
   rate of reads against the independent reader, and that nothing is ever
   misread.
6. Feed it images with no code: blank, noise, gradients, text. It must find
   nothing.
7. Compare `QR_ECC` and `QR_ALIGN` with ISO/IEC 18004. The encoder and the
   decoder share these tables, so an error in one would be invisible to a test
   that uses only the two of them: that is what step 1's independent reader is
   for.

**The AES-GCM in `recover.py`.** It exists so the script needs nothing
installed. `--selftest` runs FIPS-197 and NIST GCM vectors; a reviewer should
confirm the vectors are the published ones, that a flipped bit anywhere in the
ciphertext, tag, nonce or additional data is rejected, and that the tag is
compared in constant time. Timing is not a realistic attack on a script run
once, offline, by its owner, so a failure there is low severity; a failure to
reject a forgery is not.

## Run it

```
python3 recover.py --selftest
```

Then the round trip that no single-implementation test can give you: create a
vault in the page, add accounts with a few awkward characters in them, export
the file, open it with `recover.py`, print the backup, decode the printed
symbols with an independent reader, and open that text with `recover.py` too.
Do it once with the passphrase and once with the key card.

And the round trip through the scanner: print a backup and a key card, give the
pages to From paper as photos, or as a camera, and unlock with the passphrase,
then again with Scan key card. Try the key card before the sheets, and a vault
file opened with From a file. A browser can be given a video file as a fake
camera for this, and a mirrored one to test the mirror path. The vault must open
every way.

## Already known

These are in the README and are not findings: a short passphrase can be guessed
offline once someone has the file; the key card opens the vault by itself; old
copies survive a change of passphrase; memory cannot be wiped from JavaScript;
the printed backup shows its label, date, size and account count in the clear;
`recover.py`, the QR encoder and the QR decoder are hand-written and not
independently audited; the scanner shares a page, and a camera permission, with
the vault; a hosted copy is only as trustworthy as its host.

## Report like this

For each finding: a severity (Critical, High, Medium, Low or Info), where it is
(function name and what it does), what is wrong, what an attacker or an
unlucky owner can do with it, and what you would change. Then, separately, one
line for each of the claims above: verified, not verified, or contradicted, and
why.

Say what you could not check. A review that lists the limits of its own
reading is worth more than one that sounds certain.

Report privately through GitHub's private vulnerability reporting on this
repository, not in a public issue.
