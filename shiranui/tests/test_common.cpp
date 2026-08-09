// SPDX-License-Identifier: MIT
#include "harness.hpp"

using namespace shiranui;

TEST("hex round-trip") {
    Bytes data = {0x00, 0x01, 0x7f, 0x80, 0xff, 0xde, 0xad};
    std::string hex = toHex(ByteView(data.data(), data.size()));
    CHECK_EQ(hex, std::string("00017f80ffdead"));
    auto back = fromHex(hex);
    CHECK(back.has_value());
    CHECK(*back == data);
    CHECK(!fromHex("abc").has_value());      // odd length
    CHECK(!fromHex("zz").has_value());       // not hex
}

TEST("glob matching") {
    CHECK(globMatch("*.exe", "malware.exe"));
    CHECK(globMatch("*.EXE", "malware.exe"));           // case-insensitive
    CHECK(globMatch("C:\\Windows\\*", "C:\\Windows\\System32\\x.dll"));
    CHECK(globMatch("a?c", "abc"));
    CHECK(!globMatch("a?c", "ac"));
    CHECK(globMatch("*", ""));
    CHECK(globMatch("**", "anything"));
    CHECK(!globMatch("*.exe", "exe"));
    CHECK(globMatch("*a*b*c*", "xxaxxbxxcxx"));
    CHECK(!globMatch("*a*b*c*", "xxaxxcxxbxx"));
    // Backtracking stress: a naive matcher goes exponential here.
    CHECK(!globMatch("*a*a*a*a*a*a*a*b", std::string(64, 'a').c_str()));
}

TEST("constant-time comparison agrees with memcmp") {
    Bytes a = {1, 2, 3, 4};
    Bytes b = {1, 2, 3, 4};
    Bytes c = {1, 2, 3, 5};
    Bytes d = {1, 2, 3};
    CHECK(constantTimeEquals(ByteView(a.data(), a.size()), ByteView(b.data(), b.size())));
    CHECK(!constantTimeEquals(ByteView(a.data(), a.size()), ByteView(c.data(), c.size())));
    CHECK(!constantTimeEquals(ByteView(a.data(), a.size()), ByteView(d.data(), d.size())));
}

TEST("string helpers") {
    CHECK(startsWith("shiranui", "shira"));
    CHECK(!startsWith("shira", "shiranui"));
    CHECK(endsWith("malware.exe", ".exe"));
    CHECK(iEqualsAscii("KERNEL32.DLL", "kernel32.dll"));
    CHECK_EQ(std::string(trim("  padded  ")), std::string("padded"));
    CHECK_EQ(toLowerAscii("ABC123"), std::string("abc123"));

    auto parts = split("a,b,,c", ',');
    CHECK_EQ(parts.size(), std::size_t(3));
    auto withEmpty = split("a,b,,c", ',', true);
    CHECK_EQ(withEmpty.size(), std::size_t(4));
    CHECK_EQ(join({"a", "b", "c"}, "-"), std::string("a-b-c"));
}

TEST("json escaping covers control characters") {
    CHECK_EQ(jsonEscape("a\"b"), std::string("a\\\"b"));
    CHECK_EQ(jsonEscape("a\\b"), std::string("a\\\\b"));
    CHECK_EQ(jsonEscape("a\nb"), std::string("a\\nb"));
    CHECK_EQ(jsonEscape("a\tb"), std::string("a\\tb"));
    // A raw control byte must not be emitted literally into JSON.
    std::string escaped = jsonEscape(std::string("a\x01"));
    CHECK(escaped.find('\x01') == std::string::npos);
}

TEST("human-readable sizes") {
    CHECK_EQ(humanSize(0), std::string("0 B"));
    CHECK_EQ(humanSize(512), std::string("512 B"));
    CHECK(humanSize(1024).find("KiB") != std::string::npos);
    CHECK(humanSize(1024ull * 1024 * 1024 * 3).find("GiB") != std::string::npos);
}

TEST("secureZero actually clears") {
    Bytes secret = {0xde, 0xad, 0xbe, 0xef};
    secureZero(secret.data(), secret.size());
    for (u8 b : secret) CHECK_EQ(int(b), 0);
}

TEST("mapped file reads content and honours the size cap") {
    fs::path tmp = fs::temp_directory_path() / "shiranui_mapped_test.bin";
    {
        std::string payload(5000, 'A');
        FILE* f = std::fopen(pathToUtf8(tmp).c_str(), "wb");
        CHECK(f != nullptr);
        if (f) {
            std::fwrite(payload.data(), 1, payload.size(), f);
            std::fclose(f);
        }
    }
    auto full = MappedFile::open(tmp);
    CHECK(full.ok());
    if (full) CHECK_EQ(full->size(), std::size_t(5000));

    auto capped = MappedFile::open(tmp, 1000);
    CHECK(capped.ok());
    if (capped) CHECK_EQ(capped->size(), std::size_t(1000));

    std::error_code ec;
    fs::remove(tmp, ec);

    auto missing = MappedFile::open(tmp / "does-not-exist");
    CHECK(!missing.ok());
}
