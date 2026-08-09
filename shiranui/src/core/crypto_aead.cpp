// SPDX-License-Identifier: MIT
// AES-256-GCM per NIST SP 800-38D / FIPS 197.
//
// Design note: this is a compact, portable, *verified* implementation used for
// quarantine containers. It uses the byte-oriented S-box rather than T-tables,
// which avoids the large cache-timing surface of table-driven AES at the cost
// of throughput. Quarantine encryption is not a hot path, so that trade is
// correct here. See docs/SECURITY.md for the threat model.
#include <cstring>

#include "shiranui/crypto.hpp"

namespace shiranui::crypto::aead {

namespace {

// --------------------------- AES-256 core ---------------------------------
const u8 kSbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

inline u8 xtime(u8 x) { return static_cast<u8>((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00)); }

inline u8 gmul(u8 a, u8 b) {
    u8 r = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) r ^= a;
        a = xtime(a);
        b = static_cast<u8>(b >> 1);
    }
    return r;
}

struct Aes256 {
    static constexpr int kRounds = 14;
    u8 rk[(kRounds + 1) * 16]{};

    void setKey(const u8 key[32]) {
        std::memcpy(rk, key, 32);
        const int Nk = 8, Nb = 4, Nr = kRounds;
        u8 rcon = 1;
        for (int i = Nk; i < Nb * (Nr + 1); ++i) {
            u8 t[4];
            std::memcpy(t, rk + 4 * (i - 1), 4);
            if (i % Nk == 0) {
                u8 tmp = t[0];
                t[0] = static_cast<u8>(kSbox[t[1]] ^ rcon);
                t[1] = kSbox[t[2]];
                t[2] = kSbox[t[3]];
                t[3] = kSbox[tmp];
                rcon = xtime(rcon);
            } else if (i % Nk == 4) {
                for (int j = 0; j < 4; ++j) t[j] = kSbox[t[j]];
            }
            for (int j = 0; j < 4; ++j) rk[4 * i + j] = static_cast<u8>(rk[4 * (i - Nk) + j] ^ t[j]);
        }
    }

    void encryptBlock(const u8 in[16], u8 out[16]) const {
        u8 s[16];
        std::memcpy(s, in, 16);
        for (int i = 0; i < 16; ++i) s[i] ^= rk[i];
        for (int round = 1; round <= kRounds; ++round) {
            for (int i = 0; i < 16; ++i) s[i] = kSbox[s[i]];
            // ShiftRows (state is column-major: s[c*4 + r])
            u8 t[16];
            for (int c = 0; c < 4; ++c)
                for (int r = 0; r < 4; ++r) t[c * 4 + r] = s[((c + r) % 4) * 4 + r];
            std::memcpy(s, t, 16);
            if (round != kRounds) {
                for (int c = 0; c < 4; ++c) {
                    u8* col = s + 4 * c;
                    u8  a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                    col[0] = static_cast<u8>(gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3);
                    col[1] = static_cast<u8>(a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3);
                    col[2] = static_cast<u8>(a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3));
                    col[3] = static_cast<u8>(gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2));
                }
            }
            for (int i = 0; i < 16; ++i) s[i] ^= rk[16 * round + i];
        }
        std::memcpy(out, s, 16);
    }

    ~Aes256() { secureZero(rk, sizeof rk); }
};

// --------------------------- GHASH ----------------------------------------
void gfMul(u8 z[16], const u8 x[16], const u8 y[16]) {
    u8 v[16], r[16] = {0};
    std::memcpy(v, y, 16);
    for (int i = 0; i < 128; ++i) {
        if ((x[i >> 3] >> (7 - (i & 7))) & 1)
            for (int j = 0; j < 16; ++j) r[j] ^= v[j];
        bool lsb = (v[15] & 1) != 0;
        for (int j = 15; j > 0; --j) v[j] = static_cast<u8>((v[j] >> 1) | (v[j - 1] << 7));
        v[0] = static_cast<u8>(v[0] >> 1);
        if (lsb) v[0] ^= 0xe1;
    }
    std::memcpy(z, r, 16);
}

struct Ghash {
    u8 h[16];
    u8 y[16] = {0};

    explicit Ghash(const u8 hkey[16]) { std::memcpy(h, hkey, 16); }

    void updateBlocks(const u8* data, std::size_t len) {
        std::size_t off = 0;
        while (off < len) {
            u8          blk[16] = {0};
            std::size_t take    = (len - off < 16) ? len - off : 16;
            std::memcpy(blk, data + off, take);
            for (int i = 0; i < 16; ++i) y[i] ^= blk[i];
            u8 tmp[16];
            gfMul(tmp, y, h);
            std::memcpy(y, tmp, 16);
            off += take;
        }
    }

    void lengthBlock(u64 aadBits, u64 ctBits) {
        u8 blk[16];
        for (int i = 0; i < 8; ++i) blk[i]     = static_cast<u8>(aadBits >> (56 - 8 * i));
        for (int i = 0; i < 8; ++i) blk[8 + i] = static_cast<u8>(ctBits >> (56 - 8 * i));
        for (int i = 0; i < 16; ++i) y[i] ^= blk[i];
        u8 tmp[16];
        gfMul(tmp, y, h);
        std::memcpy(y, tmp, 16);
    }
};

inline void inc32(u8 ctr[16]) {
    for (int i = 15; i >= 12; --i)
        if (++ctr[i] != 0) break;
}

void gcmCore(const Key& key, const Nonce& nonce, ByteView aad, const u8* input, std::size_t len,
             u8* output, Tag& tag) {
    Aes256 aes;
    aes.setKey(key.data());

    u8 h[16] = {0};
    aes.encryptBlock(h, h);

    // 96-bit IV: J0 = IV || 0^31 || 1
    u8 j0[16] = {0};
    std::memcpy(j0, nonce.data(), nonce.size());
    j0[15] = 1;

    u8 ctr[16];
    std::memcpy(ctr, j0, 16);

    for (std::size_t off = 0; off < len; off += 16) {
        inc32(ctr);
        u8 ks[16];
        aes.encryptBlock(ctr, ks);
        std::size_t take = (len - off < 16) ? len - off : 16;
        for (std::size_t i = 0; i < take; ++i) output[off + i] = static_cast<u8>(input[off + i] ^ ks[i]);
        secureZero(ks, sizeof ks);
    }

    Ghash gh(h);
    gh.updateBlocks(aad.data(), aad.size());
    gh.updateBlocks(output, len);
    gh.lengthBlock(static_cast<u64>(aad.size()) * 8, static_cast<u64>(len) * 8);

    u8 s[16];
    aes.encryptBlock(j0, s);
    for (int i = 0; i < 16; ++i) tag[static_cast<std::size_t>(i)] = static_cast<u8>(gh.y[i] ^ s[i]);
    secureZero(s, sizeof s);
    secureZero(h, sizeof h);
}

}  // namespace

void seal(const Key& key, const Nonce& nonce, ByteView aad, ByteView plain, Bytes& cipher, Tag& tag) {
    cipher.assign(plain.size(), 0);
    gcmCore(key, nonce, aad, plain.data(), plain.size(), cipher.data(), tag);
}

bool open(const Key& key, const Nonce& nonce, ByteView aad, ByteView cipher, const Tag& tag,
          Bytes& plain) {
    Bytes tmp(cipher.size(), 0);
    Tag   expect{};
    // Decryption is CTR over the ciphertext; GHASH is computed over ciphertext,
    // so we recompute the tag from the *input* buffer before releasing plaintext.
    {
        Aes256 aes;
        aes.setKey(key.data());
        u8 h[16] = {0};
        aes.encryptBlock(h, h);
        u8 j0[16] = {0};
        std::memcpy(j0, nonce.data(), nonce.size());
        j0[15] = 1;

        Ghash gh(h);
        gh.updateBlocks(aad.data(), aad.size());
        gh.updateBlocks(cipher.data(), cipher.size());
        gh.lengthBlock(static_cast<u64>(aad.size()) * 8, static_cast<u64>(cipher.size()) * 8);
        u8 s[16];
        aes.encryptBlock(j0, s);
        for (int i = 0; i < 16; ++i) expect[static_cast<std::size_t>(i)] = static_cast<u8>(gh.y[i] ^ s[i]);

        if (!constantTimeEquals(ByteView(expect.data(), expect.size()),
                                ByteView(tag.data(), tag.size()))) {
            secureZero(s, sizeof s);
            plain.clear();
            return false;
        }

        u8 ctr[16];
        std::memcpy(ctr, j0, 16);
        for (std::size_t off = 0; off < cipher.size(); off += 16) {
            inc32(ctr);
            u8 ks[16];
            aes.encryptBlock(ctr, ks);
            std::size_t take = (cipher.size() - off < 16) ? cipher.size() - off : 16;
            for (std::size_t i = 0; i < take; ++i)
                tmp[off + i] = static_cast<u8>(cipher[off + i] ^ ks[i]);
            secureZero(ks, sizeof ks);
        }
        secureZero(s, sizeof s);
    }
    plain = std::move(tmp);
    return true;
}

}  // namespace shiranui::crypto::aead
