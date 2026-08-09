// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <string>

#include "shiranui/common.hpp"

namespace shiranui::crypto {

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------
class Sha256 {
public:
    static constexpr std::size_t kDigestSize = 32;
    using Digest = std::array<u8, kDigestSize>;

    Sha256() { reset(); }
    void   reset();
    void   update(ByteView data);
    Digest finish();

    static Digest      hash(ByteView data);
    static std::string hex(ByteView data);

private:
    void transform(const u8 block[64]);

    u32   state_[8]{};
    u64   bitLen_ = 0;
    u8    buffer_[64]{};
    std::size_t bufLen_ = 0;
};

// ---------------------------------------------------------------------------
// MD5 (RFC 1321) — retained only for imphash compatibility with threat-intel
// tooling. It is NEVER used for integrity or authentication in this project.
// ---------------------------------------------------------------------------
class Md5 {
public:
    static constexpr std::size_t kDigestSize = 16;
    using Digest = std::array<u8, kDigestSize>;

    Md5() { reset(); }
    void   reset();
    void   update(ByteView data);
    Digest finish();

    static Digest      hash(ByteView data);
    static std::string hex(ByteView data);

private:
    void transform(const u8 block[64]);

    u32         state_[4]{};
    u64         bitLen_ = 0;
    u8          buffer_[64]{};
    std::size_t bufLen_ = 0;
};

// ---------------------------------------------------------------------------
// AES-256-GCM (NIST SP 800-38D) — used for quarantine container encryption.
// ---------------------------------------------------------------------------
namespace aead {

constexpr std::size_t kKeySize   = 32;
constexpr std::size_t kNonceSize = 12;
constexpr std::size_t kTagSize   = 16;

using Key   = std::array<u8, kKeySize>;
using Nonce = std::array<u8, kNonceSize>;
using Tag   = std::array<u8, kTagSize>;

/// Encrypts `plain` in place into `cipher` (resized) and produces `tag`.
void seal(const Key& key, const Nonce& nonce, ByteView aad, ByteView plain, Bytes& cipher, Tag& tag);

/// Verifies `tag` and decrypts into `plain`. Returns false on authentication
/// failure, in which case `plain` is left empty.
[[nodiscard]] bool open(const Key& key, const Nonce& nonce, ByteView aad, ByteView cipher,
                        const Tag& tag, Bytes& plain);

}  // namespace aead

// ---------------------------------------------------------------------------
// Key derivation & randomness
// ---------------------------------------------------------------------------
/// HMAC-SHA256 (RFC 2104).
std::array<u8, 32> hmacSha256(ByteView key, ByteView message);

/// PBKDF2-HMAC-SHA256 (RFC 8018). Used to wrap the quarantine master key.
Bytes pbkdf2Sha256(ByteView password, ByteView salt, u32 iterations, std::size_t outLen);

/// Cryptographically secure random bytes (BCryptGenRandom / getrandom).
/// Throws std::runtime_error if the platform CSPRNG is unavailable — a security
/// product must never silently fall back to a weak source.
Bytes randomBytes(std::size_t n);

}  // namespace shiranui::crypto
