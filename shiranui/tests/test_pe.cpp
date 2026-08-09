// SPDX-License-Identifier: MIT
#include "harness.hpp"

#include <random>

#include "shiranui/pe.hpp"

using namespace shiranui;

namespace {

void put16(Bytes& b, std::size_t at, u16 v) {
    b[at]     = static_cast<u8>(v);
    b[at + 1] = static_cast<u8>(v >> 8);
}
void put32(Bytes& b, std::size_t at, u32 v) {
    for (int i = 0; i < 4; ++i) b[at + i] = static_cast<u8>(v >> (8 * i));
}
void put64(Bytes& b, std::size_t at, u64 v) {
    for (int i = 0; i < 8; ++i) b[at + i] = static_cast<u8>(v >> (8 * i));
}

/// Builds a minimal but structurally valid PE32+ image with two sections.
/// Hand-rolled rather than checked in as a binary blob so the test can perturb
/// individual fields and assert on the parser's reaction.
Bytes buildPe64(bool writableExecutableSection = false) {
    constexpr u32 kPeOffset      = 0x80;
    constexpr u32 kSectionCount  = 2;
    constexpr u32 kOptionalSize  = 240;   // PE32+ header with 16 data directories
    const u32 sectionTableOffset = kPeOffset + 24 + kOptionalSize;
    const u32 headersSize        = 0x400;
    const u32 textRaw            = headersSize;
    const u32 textSize           = 0x200;
    const u32 dataRaw            = textRaw + textSize;
    const u32 dataSize           = 0x200;

    Bytes image(dataRaw + dataSize, 0);

    image[0] = 'M';
    image[1] = 'Z';
    put32(image, 0x3C, kPeOffset);

    image[kPeOffset + 0] = 'P';
    image[kPeOffset + 1] = 'E';
    put16(image, kPeOffset + 4, 0x8664);              // machine: x64
    put16(image, kPeOffset + 6, kSectionCount);
    put32(image, kPeOffset + 8, 0x66B00000);          // timestamp
    put16(image, kPeOffset + 20, kOptionalSize);
    put16(image, kPeOffset + 22, 0x0022);             // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    const std::size_t opt = kPeOffset + 24;
    put16(image, opt + 0, 0x020B);                    // PE32+ magic
    put32(image, opt + 16, 0x1000);                   // AddressOfEntryPoint
    put32(image, opt + 20, 0x1000);                   // BaseOfCode
    put64(image, opt + 24, 0x140000000ULL);           // ImageBase
    put32(image, opt + 32, 0x1000);                   // SectionAlignment
    put32(image, opt + 36, 0x200);                    // FileAlignment
    put16(image, opt + 40, 6);                        // MajorOSVersion
    put32(image, opt + 56, 0x3000);                   // SizeOfImage
    put32(image, opt + 60, headersSize);              // SizeOfHeaders
    put16(image, opt + 68, 3);                        // Subsystem: console
    put16(image, opt + 70, 0x0160);                   // DllCharacteristics: DYNAMIC_BASE|NX|CF_GUARD
    put32(image, opt + 108, 16);                      // NumberOfRvaAndSizes

    auto writeSection = [&](std::size_t index, const char* name, u32 va, u32 vsize, u32 raw,
                            u32 rawSize, u32 characteristics) {
        std::size_t at = sectionTableOffset + index * 40;
        for (int i = 0; i < 8 && name[i]; ++i) image[at + i] = static_cast<u8>(name[i]);
        put32(image, at + 8, vsize);
        put32(image, at + 12, va);
        put32(image, at + 16, rawSize);
        put32(image, at + 20, raw);
        put32(image, at + 36, characteristics);
    };
    writeSection(0, ".text", 0x1000, textSize, textRaw, textSize, 0x60000020);
    writeSection(1, ".data", 0x2000, dataSize, dataRaw, dataSize,
                 writableExecutableSection ? 0xE0000040u : 0xC0000040u);

    for (u32 i = 0; i < textSize; ++i) image[textRaw + i] = static_cast<u8>(0x90 + (i % 3));
    return image;
}

}  // namespace

TEST("PE detection rejects non-PE input") {
    CHECK(!pe::looksLikePe(ByteView{}));
    Bytes text(200, 'A');
    CHECK(!pe::looksLikePe(ByteView(text.data(), text.size())));
    Bytes mzOnly = {'M', 'Z'};
    CHECK(!pe::looksLikePe(ByteView(mzOnly.data(), mzOnly.size())));
}

TEST("PE parser reads a synthetic PE32+ image") {
    Bytes    image = buildPe64();
    ByteView view(image.data(), image.size());
    CHECK(pe::looksLikePe(view));

    pe::Info info = pe::parse(view);
    CHECK(info.valid);
    CHECK(info.is64Bit);
    CHECK(!info.isDll);
    CHECK(!info.isDriver);
    CHECK_EQ(info.machine == pe::Machine::Amd64, true);
    CHECK_EQ(info.imageBase, 0x140000000ULL);
    CHECK_EQ(info.entryPointRva, 0x1000u);
    CHECK_EQ(info.sections.size(), std::size_t(2));
    if (info.sections.size() == 2) {
        CHECK_EQ(info.sections[0].name, std::string(".text"));
        CHECK(info.sections[0].executable());
        CHECK(!info.sections[0].writable());
        CHECK_EQ(info.sections[1].name, std::string(".data"));
        CHECK(info.sections[1].writable());
    }
    CHECK_EQ(info.entryPointSection, 0);
}

TEST("PE parser flags a writable+executable section") {
    Bytes    clean = buildPe64(false);
    Bytes    wx    = buildPe64(true);
    pe::Info a     = pe::parse(ByteView(clean.data(), clean.size()));
    pe::Info b     = pe::parse(ByteView(wx.data(), wx.size()));

    auto mentionsWx = [](const pe::Info& info) {
        for (const std::string& s : info.anomalies)
            if (s.find("W+X") != std::string::npos || s.find("writable") != std::string::npos)
                return true;
        return false;
    };
    CHECK(!mentionsWx(a));
    CHECK(mentionsWx(b));
}

TEST("PE parser reports a checksum mismatch rather than trusting the header") {
    Bytes    image = buildPe64();
    pe::Info info  = pe::parse(ByteView(image.data(), image.size()));
    // The synthetic image carries checksum 0, which is legal but does not match
    // the computed value; the parser must not silently accept it.
    CHECK(!info.checksumValid);
    CHECK(info.computedChecksum != 0);
}

TEST("PE parser survives truncation at every offset") {
    Bytes full = buildPe64();
    for (std::size_t len = 0; len < full.size(); len += 7) {
        pe::Info info = pe::parse(ByteView(full.data(), len));
        // No assertion on the outcome: the requirement is that parsing an
        // arbitrarily truncated image terminates without reading out of bounds.
        (void)info;
    }
    CHECK(true);
}

TEST("PE parser survives bit-level mutation") {
    Bytes        base = buildPe64();
    std::mt19937 rng(4242);
    for (int iteration = 0; iteration < 600; ++iteration) {
        Bytes mutated = base;
        int   edits   = 1 + static_cast<int>(rng() % 6);
        for (int e = 0; e < edits; ++e) {
            std::size_t at = rng() % mutated.size();
            switch (rng() % 3) {
                case 0: mutated[at] ^= static_cast<u8>(1u << (rng() % 8)); break;
                case 1: mutated[at] = static_cast<u8>(rng()); break;
                default: mutated[at] = 0xFF; break;
            }
        }
        pe::Info info = pe::parse(ByteView(mutated.data(), mutated.size()));
        // Whatever it decides, the section count must stay inside the parser's
        // own budget: an unbounded value here would mean a length field from the
        // file drove an allocation.
        CHECK(info.sections.size() <= 96);
    }
}

TEST("PE parser does not allocate on attacker-controlled counts") {
    Bytes image = buildPe64();
    // Claim 65535 sections in a file that clearly cannot hold them.
    put16(image, 0x80 + 6, 0xFFFF);
    pe::Info info = pe::parse(ByteView(image.data(), image.size()));
    CHECK(info.sections.size() <= 96);
}

TEST("imphash is empty when there are no imports") {
    Bytes    image = buildPe64();
    pe::Info info  = pe::parse(ByteView(image.data(), image.size()));
    CHECK(info.imports.empty());
    CHECK(info.imphash.empty());
}
