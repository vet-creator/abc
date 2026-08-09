// SPDX-License-Identifier: MIT
#include "shiranui/crypto.hpp"

#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <bcrypt.h>
#else
#  include <cerrno>
#  include <cstdio>
#endif

namespace shiranui::crypto {

namespace {
inline u32 rotr32(u32 x, int n) { return (x >> n) | (x << (32 - n)); }
inline u32 rotl32(u32 x, int n) { return (x << n) | (x >> (32 - n)); }

inline void store32be(u8* p, u32 v) {
    p[0] = static_cast<u8>(v >> 24); p[1] = static_cast<u8>(v >> 16);
    p[2] = static_cast<u8>(v >> 8);  p[3] = static_cast<u8>(v);
}
inline void store64be(u8* p, u64 v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<u8>(v >> (56 - 8 * i));
}
inline u32 load32be(const u8* p) {
    return (static_cast<u32>(p[0]) << 24) | (static_cast<u32>(p[1]) << 16) |
           (static_cast<u32>(p[2]) << 8) | static_cast<u32>(p[3]);
}
inline void store32le(u8* p, u32 v) {
    p[0] = static_cast<u8>(v); p[1] = static_cast<u8>(v >> 8);
    p[2] = static_cast<u8>(v >> 16); p[3] = static_cast<u8>(v >> 24);
}
inline u32 load32le(const u8* p) {
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
           (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
}

const u32 kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};
}  // namespace

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------
void Sha256::reset() {
    state_[0] = 0x6a09e667u; state_[1] = 0xbb67ae85u; state_[2] = 0x3c6ef372u;
    state_[3] = 0xa54ff53au; state_[4] = 0x510e527fu; state_[5] = 0x9b05688cu;
    state_[6] = 0x1f83d9abu; state_[7] = 0x5be0cd19u;
    bitLen_ = 0;
    bufLen_ = 0;
}

void Sha256::transform(const u8 block[64]) {
    u32 w[64];
    for (int i = 0; i < 16; ++i) w[i] = load32be(block + 4 * i);
    for (int i = 16; i < 64; ++i) {
        u32 s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        u32 s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i]   = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u32 a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    u32 e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (int i = 0; i < 64; ++i) {
        u32 S1    = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        u32 ch    = (e & f) ^ (~e & g);
        u32 temp1 = h + S1 + ch + kSha256K[i] + w[i];
        u32 S0    = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        u32 maj   = (a & b) ^ (a & c) ^ (b & c);
        u32 temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
}

void Sha256::update(ByteView data) {
    const u8*   p = data.data();
    std::size_t n = data.size();
    bitLen_ += static_cast<u64>(n) * 8;
    if (bufLen_) {
        std::size_t need = 64 - bufLen_;
        std::size_t take = (n < need) ? n : need;
        std::memcpy(buffer_ + bufLen_, p, take);
        bufLen_ += take;
        p += take;
        n -= take;
        if (bufLen_ == 64) { transform(buffer_); bufLen_ = 0; }
    }
    while (n >= 64) { transform(p); p += 64; n -= 64; }
    if (n) { std::memcpy(buffer_, p, n); bufLen_ = n; }
}

Sha256::Digest Sha256::finish() {
    u64 len = bitLen_;
    u8  pad = 0x80;
    update(ByteView(&pad, 1));
    bitLen_ = len;  // padding must not affect the recorded length
    u8 zero = 0x00;
    while (bufLen_ != 56) { update(ByteView(&zero, 1)); bitLen_ = len; }
    u8 lenBuf[8];
    store64be(lenBuf, len);
    std::memcpy(buffer_ + 56, lenBuf, 8);
    transform(buffer_);
    Digest out{};
    for (int i = 0; i < 8; ++i) store32be(out.data() + 4 * i, state_[i]);
    secureZero(buffer_, sizeof buffer_);
    return out;
}

Sha256::Digest Sha256::hash(ByteView data) {
    Sha256 h;
    h.update(data);
    return h.finish();
}

std::string Sha256::hex(ByteView data) {
    Digest d = hash(data);
    return toHex(ByteView(d.data(), d.size()));
}

// ---------------------------------------------------------------------------
// MD5
// ---------------------------------------------------------------------------
namespace {
const u32 kMd5K[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au, 0xa8304613u,
    0xfd469501u, 0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u,
    0xa679438eu, 0x49b40821u, 0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau, 0xd62f105du,
    0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u, 0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au, 0xfffa3942u, 0x8771f681u, 0x6d9d6122u,
    0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u, 0x289b7ec6u, 0xeaa127fau,
    0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u, 0xf4292244u,
    0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u, 0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu,
    0xeb86d391u};
const int kMd5S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                       5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
}  // namespace

void Md5::reset() {
    state_[0] = 0x67452301u; state_[1] = 0xefcdab89u;
    state_[2] = 0x98badcfeu; state_[3] = 0x10325476u;
    bitLen_ = 0;
    bufLen_ = 0;
}

void Md5::transform(const u8 block[64]) {
    u32 m[16];
    for (int i = 0; i < 16; ++i) m[i] = load32le(block + 4 * i);
    u32 a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    for (int i = 0; i < 64; ++i) {
        u32 f;
        int g;
        if (i < 16)      { f = (b & c) | (~b & d);        g = i; }
        else if (i < 32) { f = (d & b) | (~d & c);        g = (5 * i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d;                 g = (3 * i + 5) % 16; }
        else             { f = c ^ (b | ~d);              g = (7 * i) % 16; }
        u32 tmp = d;
        d = c;
        c = b;
        b = b + rotl32(a + f + kMd5K[i] + m[g], kMd5S[i]);
        a = tmp;
    }
    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
}

void Md5::update(ByteView data) {
    const u8*   p = data.data();
    std::size_t n = data.size();
    bitLen_ += static_cast<u64>(n) * 8;
    if (bufLen_) {
        std::size_t need = 64 - bufLen_;
        std::size_t take = (n < need) ? n : need;
        std::memcpy(buffer_ + bufLen_, p, take);
        bufLen_ += take;
        p += take;
        n -= take;
        if (bufLen_ == 64) { transform(buffer_); bufLen_ = 0; }
    }
    while (n >= 64) { transform(p); p += 64; n -= 64; }
    if (n) { std::memcpy(buffer_, p, n); bufLen_ = n; }
}

Md5::Digest Md5::finish() {
    u64 len = bitLen_;
    u8  pad = 0x80;
    update(ByteView(&pad, 1));
    bitLen_ = len;
    u8 zero = 0x00;
    while (bufLen_ != 56) { update(ByteView(&zero, 1)); bitLen_ = len; }
    for (int i = 0; i < 8; ++i) buffer_[56 + i] = static_cast<u8>(len >> (8 * i));
    transform(buffer_);
    Digest out{};
    for (int i = 0; i < 4; ++i) store32le(out.data() + 4 * i, state_[i]);
    secureZero(buffer_, sizeof buffer_);
    return out;
}

Md5::Digest Md5::hash(ByteView data) {
    Md5 h;
    h.update(data);
    return h.finish();
}

std::string Md5::hex(ByteView data) {
    Digest d = hash(data);
    return toHex(ByteView(d.data(), d.size()));
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 / PBKDF2
// ---------------------------------------------------------------------------
std::array<u8, 32> hmacSha256(ByteView key, ByteView message) {
    u8 k[64] = {};
    if (key.size() > 64) {
        auto d = Sha256::hash(key);
        std::memcpy(k, d.data(), d.size());
    } else if (!key.empty()) {
        std::memcpy(k, key.data(), key.size());
    }
    u8 ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = static_cast<u8>(k[i] ^ 0x36);
        opad[i] = static_cast<u8>(k[i] ^ 0x5c);
    }
    Sha256 inner;
    inner.update(ByteView(ipad, 64));
    inner.update(message);
    auto innerDigest = inner.finish();

    Sha256 outer;
    outer.update(ByteView(opad, 64));
    outer.update(ByteView(innerDigest.data(), innerDigest.size()));
    auto result = outer.finish();

    secureZero(k, sizeof k);
    secureZero(ipad, sizeof ipad);
    secureZero(opad, sizeof opad);
    return result;
}

Bytes pbkdf2Sha256(ByteView password, ByteView salt, u32 iterations, std::size_t outLen) {
    if (iterations == 0) iterations = 1;
    Bytes out;
    out.reserve(outLen);
    u32 block = 1;
    while (out.size() < outLen) {
        Bytes saltBlock(salt.begin(), salt.end());
        saltBlock.push_back(static_cast<u8>(block >> 24));
        saltBlock.push_back(static_cast<u8>(block >> 16));
        saltBlock.push_back(static_cast<u8>(block >> 8));
        saltBlock.push_back(static_cast<u8>(block));
        auto u = hmacSha256(password, ByteView(saltBlock.data(), saltBlock.size()));
        auto t = u;
        for (u32 i = 1; i < iterations; ++i) {
            u = hmacSha256(password, ByteView(u.data(), u.size()));
            for (std::size_t j = 0; j < t.size(); ++j) t[j] ^= u[j];
        }
        std::size_t take = (outLen - out.size() < t.size()) ? outLen - out.size() : t.size();
        out.insert(out.end(), t.begin(), t.begin() + static_cast<std::ptrdiff_t>(take));
        ++block;
    }
    return out;
}

// ---------------------------------------------------------------------------
// CSPRNG
// ---------------------------------------------------------------------------
Bytes randomBytes(std::size_t n) {
    Bytes out(n);
    if (n == 0) return out;
#ifdef _WIN32
    NTSTATUS st = ::BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(n),
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) throw std::runtime_error("BCryptGenRandom failed");
#else
    std::FILE* f = std::fopen("/dev/urandom", "rb");
    if (!f) throw std::runtime_error("cannot open /dev/urandom");
    std::size_t got = std::fread(out.data(), 1, n, f);
    std::fclose(f);
    if (got != n) throw std::runtime_error("short read from /dev/urandom");
#endif
    return out;
}

}  // namespace shiranui::crypto
