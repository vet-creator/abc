# Security design notes

This document records the threat model SHIRANUI was built against, the
cryptographic decisions it makes and why, and the limitations it does not
attempt to hide. A security tool whose assumptions are undocumented cannot be
evaluated, and one that cannot be evaluated should not be trusted.

---

## 1. Threat model

### 1.1 What the engine assumes about its input

**Every byte SHIRANUI parses is assumed to be hostile and constructed
specifically to break the parser.** This is the normal case, not the worst case:
the files a scanner reads are chosen by an attacker.

Concretely, the PE parser:

- never uses `<winnt.h>` structures overlaid on file data, so no field is read
  through a pointer cast into an attacker-controlled buffer;
- bounds-checks every read through a cursor that knows the buffer length;
- never lets a length field from the file drive an allocation — section,
  import, export and resource counts are all capped by constants;
- treats structural nonsense as an *observation* rather than a fatal error, so
  a malformed file is still analysed rather than skipped, which is exactly the
  behaviour a "parser-crashing" evasion attempt is trying to defeat;
- is exercised by mutation fuzzing under AddressSanitizer and
  UndefinedBehaviorSanitizer, and by truncation at every offset.

Because the engine core has no Windows dependencies, this fuzzing runs on Linux
with far better tooling than the platform it ultimately ships to.

### 1.2 What the engine assumes about the host

SHIRANUI assumes the host may already be compromised. It therefore:

- reads both the 64-bit and 32-bit registry views, since malware routinely hides
  in whichever view the reader is not looking at;
- reads scheduled task definitions from disk rather than through the Task
  Scheduler API, so a task hidden by clearing its registry index is still found;
- reports a disabled antivirus engine or a cleared tamper-protection flag as a
  finding in its own right, because those are more often the result of an
  intrusion than of a deliberate administrative choice;
- quotes the service binary path on installation, so a directory containing a
  space cannot be turned into an unquoted-service-path hijack;
- restricts its own DLL search path to System32 and enables
  termination-on-heap-corruption at startup.

### 1.3 What is explicitly out of scope

- **Blocking execution.** There is no kernel driver and no minifilter. SHIRANUI
  observes; it does not prevent.
- **Memory-resident threats.** Only files on disk and process *images* are
  examined. Injected code, reflectively loaded modules and fileless payloads
  living in another process's memory are invisible to it.
- **Rootkits.** Anything that subverts the APIs SHIRANUI calls can hide from it.
  The autorun and process enumerators trust the operating system's answers.
- **Self-protection.** A process running with equal or greater privilege can
  terminate SHIRANUI, tamper with its rules, or delete its quarantine store.
  The store's contents remain confidential and tamper-evident, but availability
  is not defended.

---

## 2. Cryptographic decisions

### 2.1 Primitives and where they are used

| Primitive | Standard | Used for |
|---|---|---|
| SHA-256 | FIPS 180-4 | File identity, hash rules, HMAC, PBKDF2 |
| HMAC-SHA256 | RFC 2104 | Per-item quarantine key derivation |
| PBKDF2-HMAC-SHA256 | RFC 8018 | Passphrase-based master key wrapping |
| AES-256-GCM | FIPS 197, SP 800-38D | Quarantine container confidentiality and integrity |
| MD5 | RFC 1321 | **Imphash compatibility only** |

**MD5 is not used for integrity or authentication anywhere.** It exists solely
because `imphash` is defined as the MD5 of a normalised import string, and an
imphash that does not match the ecosystem's value is useless. It is confined to
that one function and labelled as such in the source.

### 2.2 The AES implementation uses a byte-wise S-box

The usual fast AES software implementation uses 4 KB T-tables, whose access
pattern depends on the key and is therefore observable through the cache. This
implementation uses a plain byte-wise S-box instead, which is slower.

The tradeoff is deliberate and is a good one *here*: quarantine is not a hot
path — it happens once per detected file, on a file that is by definition
already interesting — and a cache-timing side channel in a process that runs on
a possibly-compromised host is a real exposure. Where throughput would matter,
this choice would be wrong; where it is made, it costs almost nothing.

This is not a constant-time implementation in the formal sense, and it is not
claimed to be one.

### 2.3 Randomness fails closed

`crypto::randomBytes` uses `BCryptGenRandom` on Windows and `/dev/urandom`
elsewhere. **If the platform CSPRNG is unavailable it throws.** There is no
fallback to a time seed or a PRNG. A weak key that looks like a strong key is
worse than a visible failure, because the failure gets fixed and the weak key
does not.

### 2.4 Quarantine container format

```
offset  size  field
  0       4   magic "SHQ1"
  4       2   format version
  6       2   header length H
  8      H-8  header JSON            <- authenticated as AAD, not encrypted
  H      12   nonce
 H+12    16   GCM tag
 H+28     N   ciphertext
```

Design points:

- **The header is authenticated but not encrypted.** Listing the store must not
  require decrypting every item, but the recorded origin path, size and SHA-256
  must not be silently rewritable. Passing the header as the AEAD's associated
  data achieves both: editing one byte of it makes restoration fail.
- **Each item gets its own key**, derived as
  `HMAC-SHA256(master_key, "shiranui-quarantine-v1" || item_id)`. Two identical
  files therefore produce unrelated ciphertexts, so the store does not leak the
  fact that the same sample was quarantined twice.
- **Restore verifies twice**: the GCM tag, and then the recorded SHA-256 against
  the decrypted bytes. The second check is redundant against a cryptographic
  attacker and is there to catch the far more likely case of a bug.
- **Restore never overwrites** an existing file at the destination.
- **A failed authentication yields nothing.** The plaintext buffer is cleared
  rather than returned partially decrypted.

### 2.5 The master key

The master key is 32 random bytes in `master.key` inside the store directory,
created with owner-only permissions where the platform supports them.

**This protects against another user and against offline inspection of the
quarantine files. It does not protect against an attacker who already has
administrator rights on the machine**, since they can read the key file. Binding
the key to DPAPI machine scope would raise that bar and is the obvious next
step; it is not implemented today, and this document says so rather than
implying protection that is not there.

### 2.6 Secure deletion is best-effort

`shredFile` overwrites a file's contents before unlinking it. On a modern SSD
with wear levelling, on a copy-on-write filesystem, or in the presence of
volume shadow copies, **this does not guarantee the data is unrecoverable**. It
is a best-effort measure and is described as such in the source rather than
promising more than the hardware can deliver.

---

## 3. Detection-quality commitments

### 3.1 False positives are treated as build failures

The CI pipeline scans several thousand clean system binaries and **fails the
build if anything is flagged**. This is not decoration. An engine that cries
wolf on system files trains its operator to dismiss it, which makes it worse
than no engine at all.

One real example from development: the x86 PEB-walk rule used the pattern
`{ 64 8B ?? 30 }`. The wildcard also matches ModRM bytes with `rm = 100`, where
the following byte is a SIB byte rather than the `0x30` displacement — so the
rule fired on Python bytecode. The fix enumerates the valid encodings instead of
wildcarding them, and the weaker four-byte form now additionally requires a
corroborating `PEB_LDR_DATA` field access.

### 3.2 Malware strings are stored as hex, not as literals

Rule files spell out malware markers as hex byte patterns rather than quoted
strings. The match is byte-identical, but the repository does not contain
readable copies of the indicators, so checking it out does not trip the
developer's own antivirus or a corporate DLP filter. The EICAR test string is
assembled from character codes in CI for the same reason.

### 3.3 Every detection is explainable

A detection carries its source, its rule or heuristic identifier, its weight,
the matched strings and a human-readable description. Scores are sums of
individually justified contributions, never an opaque model output. An analyst
must be able to disagree with the engine on the evidence.

### 3.4 A valid signature is a discount, not an exemption

A verified Authenticode signature subtracts from the score and the subtraction
appears in the output as its own line item. Signed malware is common enough —
through stolen certificates, abused code-signing services and legitimately
signed vulnerable drivers — that treating a certificate as proof of safety would
be an obvious bypass.

Revocation checking is **off** by default. Checking it performs network I/O per
file, which turns a full-disk scan into an outbound traffic storm and stalls
entirely on an isolated host. It is available as an explicit option.

---

## 4. Known limitations

1. **Process monitoring polls** at roughly two samples per second. A process
   that starts and exits between samples is missed. An ETW kernel session would
   close that gap; it was not used because it requires additional privileges and
   can leave an orphaned kernel session behind on an abnormal exit. The
   `backend()` method reports which mechanism is live so a caller never has to
   guess.
2. **Command lines are not read across bitness.** Reading a 32-bit process's
   PEB from a 64-bit scanner requires the WOW64 structure layout; rather than
   guess at offsets and emit silent garbage, the engine declines and reports the
   image path alone.
3. **Archives are not unpacked.** A malicious file inside a ZIP is scanned as
   the compressed bytes it is, which will usually not match.
4. **No emulation or unpacking.** A packed sample is detected *as packed* —
   high entropy, tiny import table — not by its unpacked contents.
5. **The real-time file monitor can miss short-lived files.** It also waits
   briefly before scanning so it does not read a half-written download; a file
   deleted inside that window is not examined.
6. **Symbolic links and reparse points are not followed** by default, because
   a crafted reparse loop is a cheap denial of service against any recursive
   scanner. `--follow-symlinks` opts in.

---

## 5. Reporting a vulnerability

Please report security issues privately through the repository's security
advisory page rather than as a public issue, and allow time for a fix before
disclosure.
