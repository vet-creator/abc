# SHIRANUI — 不知火

An endpoint threat detection engine for Windows, written in C++20 with no
third-party dependencies.

SHIRANUI performs static analysis of files, evaluates them against a rule
language and a set of explainable heuristics, watches directories in real time,
audits the machine's security configuration, enumerates persistence points, and
holds confirmed detections in an authenticated encrypted quarantine.

---

## What this is, and what it is not

Being precise about scope matters more in security software than anywhere else,
because the gap between what a tool appears to promise and what it actually does
is exactly where people get hurt.

**SHIRANUI is** a static analysis and monitoring engine. Everything it reports is
derived from bytes it read and settings it queried, and every detection carries
the reason it fired.

**SHIRANUI is not** a replacement for Microsoft Defender or a commercial EDR. It
has no kernel driver, so it cannot block execution — it observes and reports
after the fact. It has no cloud reputation service, no behavioural sandbox, and
no ability to remove an infection that is already resident in memory. Its
real-time file monitor polls at user level and can miss a file that is created
and deleted between two events.

Use it as a second opinion, an incident-response triage tool, a hunting engine
for a rule set you maintain yourself, and a way to see what a detection engine
is actually doing — not as your only line of defence.

---

## Building

Requires CMake 3.20+ and a C++20 compiler. No other dependencies.

```bat
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The binary lands in `build/bin/Release/shiranui.exe`, with the rule set staged
alongside it in `build/bin/Release/rules/`.

The engine core is platform-independent, so it also builds and tests on Linux
and macOS. That is not an accident: it is what allows the parsers to be fuzzed
under AddressSanitizer during development, and it is why the CI matrix runs the
entire test suite under sanitizers on Linux before shipping a Windows binary.

```sh
cmake -B build -G Ninja -DSHIRANUI_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build && ctest --test-dir build --output-on-failure
```

| CMake option | Default | Meaning |
|---|---|---|
| `SHIRANUI_BUILD_TESTS` | `ON` | Build and register the test suite |
| `SHIRANUI_WERROR` | `OFF` | Treat warnings as errors (CI enables this) |
| `SHIRANUI_SANITIZE` | `OFF` | AddressSanitizer + UndefinedBehaviorSanitizer |
| `SHIRANUI_COMMIT` | `unknown` | Revision string embedded in the binary |

---

## Usage

```
shiranui scan <path>...        Scan files or directory trees
shiranui inspect <file>        Detailed static analysis of one file
shiranui monitor <dir>...      Watch directories, scan changes as they happen
shiranui audit                 Report the machine's security posture (read-only)
shiranui autoruns              Enumerate persistence points
shiranui ps                    List running processes
shiranui quarantine <sub>      list | restore <id> | purge <id> | purge-all
shiranui rules                 Show the loaded rule set
shiranui service <sub>         status | install | uninstall | run
```

Exit codes are meaningful, which makes the tool usable from a script or a CI
pipeline: `0` nothing found, `1` malicious, `2` usage or setup error,
`3` suspicious only.

```bat
rem Scan a tree, quarantine what is clearly malicious, emit JSON for a SIEM
shiranui scan C:\Users --quarantine --json > findings.jsonl

rem Check every autorun entry's target binary
shiranui autoruns --scan

rem Watch a download directory, including the image of every process that starts
shiranui monitor C:\Users\me\Downloads --processes --quarantine
```

---

## How detection works

A file passes through four independent stages, and the verdict is the sum of
what they found.

**1. Exact hashes.** SHA-256 and, for PE files, a `pefile`-compatible imphash are
looked up against the rule set's hash entries.

**2. Rule matching.** Every string from every rule is compiled into a single
Aho-Corasick automaton with wildcard support, so scanning cost is linear in the
size of the input and essentially independent of how many rules are loaded. Two
hundred rules cost what one rule costs.

**3. PE structure.** The PE/COFF parser reads headers, sections, imports,
exports, resources, TLS callbacks, debug info, the Rich header and the overlay.
It records structural oddities — entry point outside any section, writable and
executable sections, high-entropy sections, an implausibly small import table,
ASLR or DEP or CFG switched off — as observations rather than verdicts.

**4. Heuristics.** Observations and imported-API groupings are combined into a
weighted score. Every contribution carries its own justification, because a
detection you cannot explain is a detection you cannot act on:

```
MALICIOUS  C:\Users\me\Downloads\invoice.exe  412 KiB  score 88.0
      sha256 3f2a...
      high  H.Inject.RemoteThread (+26.0)
            Imports the classic remote-thread injection sequence
            matched: OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
      medium  H.Packed.Likely (+18.0)
            .text entropy 7.91 with only 3 imported functions
```

A valid Authenticode signature reduces the score and says so in the output. It
is a discount, not an exemption — signed malware exists, and a tool that stops
looking at a file because it carries a certificate is trivially bypassed.

---

## Rule language

Rules live in `rules/*.srules`. The syntax will look familiar to anyone who has
written YARA rules.

```
rule Credential_Dumper : tool credential-access {
    meta:
        severity    = critical
        family      = "Mimikatz"
        description = "Credential-dumping toolkit artifacts"
    strings:
        $banner  = "sekurlsa::logonpasswords" nocase ascii wide
        $module  = "mimikatz" nocase
        $marker  = { 6D 69 6D 69 ?? 61 74 7A }
    condition:
        2 of them and filesize < 8MB
}

hash sha256 = 275a021b...fd0f name=EICAR.Test severity=critical family=EICAR
```

- **Strings** may be quoted literals (with `\n`, `\t`, `\r`, `\0`, `\\`, `\"`,
  `\xHH` escapes) or hex patterns with `??` wildcards.
- **Modifiers**: `nocase`, `wide` (UTF-16LE), `ascii`.
- **Conditions**: `$a`, `and`, `or`, `not`, parentheses, `N of them`,
  `all/any/none of them`, `filesize < N` with `K`/`M`/`B` suffixes.
- **Severity**: `info`, `low`, `medium`, `high`, `critical`.
- Comments start with `#` or `//` and are ignored inside string literals.

Rules may be written across several lines or on one; the parser normalises
either form.

---

## Correctness

Security software that is merely plausible is worse than no security software,
because it converts an unknown risk into a false sense of safety. Every
non-obvious component here is checked against an independent implementation
rather than against its author's expectations.

| Component | How it is verified |
|---|---|
| SHA-256, MD5, HMAC, PBKDF2 | Known-answer tests cross-checked against Python `hashlib` |
| AES-256-GCM | NIST SP 800-38D vectors plus 60 randomised cases differentially tested against the `cryptography` package |
| Aho-Corasick matcher | Differential fuzzing against a naive O(n·m) reference: 400 randomised rule sets over a deliberately small alphabet, every match compared exactly |
| PE parser | Real x86, x64 and ARM64 binaries, plus mutation fuzzing under ASan and UBSan; truncated at every offset |
| Rule engine | Parser, precedence, quantifier and modifier semantics asserted case by case |
| Quarantine | Round-trip, plus tampering with header, ciphertext, tag, nonce and associated data — each must fail closed |
| Whole engine | Scanned against thousands of clean system binaries; any detection there is treated as a CI failure |

That last row matters as much as the others. A false positive on a system
binary is not a cosmetic defect: it teaches the operator to ignore the tool.
The CI pipeline fails the build if the engine flags anything in `/usr/bin`.

Three real defects were found this way during development and are worth
recording, because each one produced plausible-looking output while being
wrong:

- The Aho-Corasick trie held a reference into a vector across a reallocation,
  so roughly 40% of matches were silently lost.
- Output-link splicing corrupted shared suffix chains, dropping overlapping
  matches.
- The fuzzy hash used a substitution cost of 1 instead of 2, which made
  completely unrelated files score around 50% similar.

A shipped rule was also found to be too broad: `{ 64 8B ?? 30 }` for an x86 PEB
walk matched ModRM bytes that introduce a SIB byte, where `0x30` is not a
displacement at all. It fired on Python bytecode. The wildcard was replaced with
the enumerated set of valid encodings, and the weaker disp8 form now requires a
corroborating `PEB_LDR_DATA` field access.

---

## Repository layout

```
include/shiranui/    Public headers
src/core/            Portable engine: crypto, analysis, PE, rules, scanner, quarantine
src/win/             Windows integration: Authenticode, posture, autoruns, watchers, service
src/cli/             Command line front end
rules/               Detection rules
tests/               Test suite (no external framework)
cmake/               Hardening and warning configuration
.github/workflows/   Build, test and release pipeline
```

---

## Licence

MIT. See `LICENSE`.

The threat model, the cryptographic choices and their justifications, and the
known limitations are documented in [`docs/SECURITY.md`](docs/SECURITY.md).
