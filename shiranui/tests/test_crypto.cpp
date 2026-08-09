// SPDX-License-Identifier: MIT
// Known-answer tests. Every vector below was cross-checked against Python's
// hashlib / the `cryptography` package before being frozen here, so a failure
// means this implementation drifted, not that the expectation is guesswork.
#include "harness.hpp"

#include "shiranui/crypto.hpp"

using namespace shiranui;

namespace {
ByteView bv(std::string_view s) {
    return ByteView(reinterpret_cast<const u8*>(s.data()), s.size());
}
Bytes hex(std::string_view s) {
    auto b = fromHex(s);
    return b ? *b : Bytes{};
}
}  // namespace

TEST("SHA-256 known answers") {
    CHECK_EQ(crypto::Sha256::hex(bv("")),
             std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(crypto::Sha256::hex(bv("abc")),
             std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_EQ(crypto::Sha256::hex(bv("a")),
             std::string("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"));
    // 55 and 56 bytes straddle the single/double padding block boundary.
    CHECK_EQ(crypto::Sha256::hex(bv(std::string(55, 'a'))),
             std::string("9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"));
    CHECK_EQ(crypto::Sha256::hex(bv(std::string(56, 'a'))),
             std::string("b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"));
    CHECK_EQ(crypto::Sha256::hex(bv("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
             std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
}

TEST("SHA-256 streaming matches one-shot") {
    std::string data(1000, 'x');
    crypto::Sha256 streaming;
    for (std::size_t i = 0; i < data.size(); i += 7)
        streaming.update(bv(std::string_view(data).substr(i, std::min<std::size_t>(7, data.size() - i))));
    auto digest = streaming.finish();
    CHECK_EQ(toHex(ByteView(digest.data(), digest.size())), crypto::Sha256::hex(bv(data)));
}

TEST("SHA-256 of one megabyte") {
    std::string big(1024 * 1024, 'a');
    CHECK_EQ(crypto::Sha256::hex(bv(big)),
             std::string("9bc1b2a288b26af7257a36277ae3816a7d4f16e89c1e7e77d0a5c48bad62b360"));
}

TEST("MD5 known answers (imphash compatibility only)") {
    CHECK_EQ(crypto::Md5::hex(bv("")), std::string("d41d8cd98f00b204e9800998ecf8427e"));
    CHECK_EQ(crypto::Md5::hex(bv("abc")), std::string("900150983cd24fb0d6963f7d28e17f72"));
    CHECK_EQ(crypto::Md5::hex(bv("The quick brown fox jumps over the lazy dog")),
             std::string("9e107d9d372bb6826bd81d3542a419d6"));
}

TEST("HMAC-SHA256 (RFC 4231)") {
    auto mac1 = crypto::hmacSha256(hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
                                       .empty()
                                       ? ByteView{}
                                       : ByteView(hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").data(), 20),
                                   bv("Hi There"));
    CHECK_EQ(toHex(ByteView(mac1.data(), mac1.size())),
             std::string("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));

    auto mac2 = crypto::hmacSha256(bv("Jefe"), bv("what do ya want for nothing?"));
    CHECK_EQ(toHex(ByteView(mac2.data(), mac2.size())),
             std::string("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
}

TEST("PBKDF2-HMAC-SHA256 (RFC 7914 style vector)") {
    Bytes key = crypto::pbkdf2Sha256(bv("password"), bv("salt"), 4096, 32);
    CHECK_EQ(toHex(ByteView(key.data(), key.size())),
             std::string("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"));

    Bytes one = crypto::pbkdf2Sha256(bv("password"), bv("salt"), 1, 32);
    CHECK_EQ(toHex(ByteView(one.data(), one.size())),
             std::string("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"));
}

TEST("AES-256-GCM (NIST SP 800-38D vectors)") {
    crypto::aead::Key   key{};
    crypto::aead::Nonce nonce{};
    Bytes               cipher;
    crypto::aead::Tag   tag{};

    // Case 13: all-zero key/IV, empty plaintext.
    crypto::aead::seal(key, nonce, ByteView{}, ByteView{}, cipher, tag);
    CHECK_EQ(cipher.size(), std::size_t(0));
    CHECK_EQ(toHex(ByteView(tag.data(), tag.size())),
             std::string("530f8afbc74536b9a963b4f1c4cb738b"));

    // Case 14: all-zero key/IV, 16 zero bytes of plaintext.
    Bytes zeros(16, 0);
    crypto::aead::seal(key, nonce, ByteView{}, ByteView(zeros.data(), zeros.size()), cipher, tag);
    CHECK_EQ(toHex(ByteView(cipher.data(), cipher.size())),
             std::string("cea7403d4d606b6e074ec5d3baf39d18"));
    CHECK_EQ(toHex(ByteView(tag.data(), tag.size())),
             std::string("d0d1c8a799996bf0265b98b5d48ab919"));

    // Case 15: real key, 64-byte plaintext, no AAD.
    Bytes keyBytes = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    Bytes ivBytes  = hex("cafebabefacedbaddecaf888");
    Bytes plain    = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                         "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
                         "1aafd255");
    CHECK_EQ(plain.size(), std::size_t(64));
    std::copy(keyBytes.begin(), keyBytes.end(), key.begin());
    std::copy(ivBytes.begin(), ivBytes.end(), nonce.begin());
    crypto::aead::seal(key, nonce, ByteView{}, ByteView(plain.data(), plain.size()), cipher, tag);
    CHECK_EQ(toHex(ByteView(cipher.data(), cipher.size())),
             std::string("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                         "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
                         "898015ad"));
    CHECK_EQ(toHex(ByteView(tag.data(), tag.size())),
             std::string("b094dac5d93471bdec1a502270e3cc6c"));
}

TEST("AES-256-GCM round-trip with associated data") {
    crypto::aead::Key   key{};
    crypto::aead::Nonce nonce{};
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<u8>(i * 7 + 1);
    for (std::size_t i = 0; i < nonce.size(); ++i) nonce[i] = static_cast<u8>(i * 3);

    std::string message = "quarantined payload";
    std::string aad     = R"({"id":"abc","sha256":"..."} )";

    Bytes             cipher, recovered;
    crypto::aead::Tag tag{};
    crypto::aead::seal(key, nonce, bv(aad), bv(message), cipher, tag);
    CHECK_EQ(cipher.size(), message.size());

    CHECK(crypto::aead::open(key, nonce, bv(aad), ByteView(cipher.data(), cipher.size()), tag,
                             recovered));
    CHECK_EQ(std::string(recovered.begin(), recovered.end()), message);
}

TEST("AES-256-GCM rejects every kind of tampering") {
    crypto::aead::Key   key{};
    crypto::aead::Nonce nonce{};
    Bytes               cipher, out;
    crypto::aead::Tag   tag{};
    std::string         message = "the quick brown fox";
    std::string         aad     = "header";

    crypto::aead::seal(key, nonce, bv(aad), bv(message), cipher, tag);

    // Flipping any single ciphertext bit must fail authentication and must not
    // leave partially decrypted plaintext behind.
    for (std::size_t i = 0; i < cipher.size(); ++i) {
        Bytes mutated = cipher;
        mutated[i] ^= 0x01;
        out.assign(4, 0xAA);
        CHECK(!crypto::aead::open(key, nonce, bv(aad), ByteView(mutated.data(), mutated.size()),
                                  tag, out));
        CHECK_EQ(out.size(), std::size_t(0));
    }

    // A modified tag must fail.
    crypto::aead::Tag badTag = tag;
    badTag[0] ^= 0x80;
    CHECK(!crypto::aead::open(key, nonce, bv(aad), ByteView(cipher.data(), cipher.size()), badTag,
                              out));

    // Modified associated data must fail: this is what protects the quarantine
    // container's recorded origin path from being rewritten.
    CHECK(!crypto::aead::open(key, nonce, bv("headeR"), ByteView(cipher.data(), cipher.size()),
                              tag, out));

    // A different nonce must fail.
    crypto::aead::Nonce otherNonce = nonce;
    otherNonce[11] ^= 0xFF;
    CHECK(!crypto::aead::open(key, otherNonce, bv(aad), ByteView(cipher.data(), cipher.size()),
                              tag, out));
}

TEST("AES-256-GCM handles lengths around the block boundary") {
    crypto::aead::Key   key{};
    crypto::aead::Nonce nonce{};
    for (std::size_t len : {0u, 1u, 15u, 16u, 17u, 31u, 32u, 33u, 63u, 64u, 65u, 1000u}) {
        Bytes plain(len);
        for (std::size_t i = 0; i < len; ++i) plain[i] = static_cast<u8>(i * 31);
        Bytes             cipher, out;
        crypto::aead::Tag tag{};
        crypto::aead::seal(key, nonce, ByteView{}, ByteView(plain.data(), plain.size()), cipher,
                           tag);
        CHECK_EQ(cipher.size(), plain.size());
        CHECK(crypto::aead::open(key, nonce, ByteView{}, ByteView(cipher.data(), cipher.size()),
                                 tag, out));
        CHECK(out == plain);
    }
}

TEST("CSPRNG produces distinct, non-trivial output") {
    Bytes a = crypto::randomBytes(32);
    Bytes b = crypto::randomBytes(32);
    CHECK_EQ(a.size(), std::size_t(32));
    CHECK(a != b);
    bool allZero = true;
    for (u8 v : a)
        if (v != 0) allZero = false;
    CHECK(!allZero);
}
