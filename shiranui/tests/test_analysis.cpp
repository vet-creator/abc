// SPDX-License-Identifier: MIT
#include "harness.hpp"

#include <random>
#include <set>

#include "shiranui/analysis.hpp"

using namespace shiranui;
using namespace shiranui::analysis;

namespace {

ByteView bv(std::string_view s) {
    return ByteView(reinterpret_cast<const u8*>(s.data()), s.size());
}

/// Reference implementation: O(n*m) scan of a hex spec that may contain "??".
/// Deliberately naive — its only job is to be obviously correct so the
/// automaton can be differentially tested against it.
std::vector<std::size_t> naiveFind(const std::vector<int>& spec, ByteView data, bool nocase) {
    std::vector<std::size_t> hits;
    if (spec.empty() || data.size() < spec.size()) return hits;
    auto fold = [nocase](u8 c) -> u8 {
        if (!nocase) return c;
        return (c >= 'A' && c <= 'Z') ? static_cast<u8>(c - 'A' + 'a') : c;
    };
    for (std::size_t i = 0; i + spec.size() <= data.size(); ++i) {
        bool ok = true;
        for (std::size_t j = 0; j < spec.size(); ++j) {
            if (spec[j] < 0) continue;   // wildcard
            if (fold(data[i + j]) != fold(static_cast<u8>(spec[j]))) {
                ok = false;
                break;
            }
        }
        if (ok) hits.push_back(i);
    }
    return hits;
}

std::string specToHex(const std::vector<int>& spec) {
    std::string out;
    for (int v : spec) {
        if (!out.empty()) out += ' ';
        if (v < 0) out += "??";
        else {
            const char* digits = "0123456789ABCDEF";
            out += digits[(v >> 4) & 0xF];
            out += digits[v & 0xF];
        }
    }
    return out;
}

}  // namespace

TEST("Shannon entropy at the extremes") {
    Bytes zeros(4096, 0);
    CHECK_NEAR(shannonEntropy(ByteView(zeros.data(), zeros.size())), 0.0, 1e-9);

    Bytes uniform(256 * 16);
    for (std::size_t i = 0; i < uniform.size(); ++i) uniform[i] = static_cast<u8>(i % 256);
    CHECK_NEAR(shannonEntropy(ByteView(uniform.data(), uniform.size())), 8.0, 1e-9);

    CHECK_NEAR(shannonEntropy(ByteView{}), 0.0, 1e-9);

    Bytes twoValues(1000);
    for (std::size_t i = 0; i < twoValues.size(); ++i) twoValues[i] = (i % 2) ? 0xFF : 0x00;
    CHECK_NEAR(shannonEntropy(ByteView(twoValues.data(), twoValues.size())), 1.0, 1e-9);
}

TEST("peak window entropy finds a high-entropy region inside low-entropy data") {
    Bytes data(20000, 'A');
    std::mt19937 rng(1234);
    for (std::size_t i = 8000; i < 12000; ++i) data[i] = static_cast<u8>(rng());
    double whole = shannonEntropy(ByteView(data.data(), data.size()));
    double peak  = peakWindowEntropy(ByteView(data.data(), data.size()), 2048);
    CHECK(peak > whole);
    CHECK(peak > 7.0);
}

TEST("printable ratio") {
    CHECK_NEAR(printableRatio(bv("hello world")), 1.0, 1e-9);
    Bytes binary(100, 0x00);
    CHECK_NEAR(printableRatio(ByteView(binary.data(), binary.size())), 0.0, 1e-9);
}

TEST("string extraction finds ASCII and UTF-16LE") {
    std::string blob = "junk\x01\x02SuspiciousString\x00more";
    Bytes data(blob.begin(), blob.end());
    // Append a UTF-16LE run.
    for (char c : std::string("WideMarkerHere")) {
        data.push_back(static_cast<u8>(c));
        data.push_back(0);
    }
    auto strings = extractStrings(ByteView(data.data(), data.size()), 6);
    bool foundAscii = false, foundWide = false;
    for (const std::string& s : strings) {
        if (s.find("SuspiciousString") != std::string::npos) foundAscii = true;
        if (s.find("WideMarkerHere") != std::string::npos) foundWide = true;
    }
    CHECK(foundAscii);
    CHECK(foundWide);
}

TEST("fuzzy hash: identical, similar and unrelated inputs") {
    std::mt19937 rng(99);
    Bytes a(30000);
    for (u8& b : a) b = static_cast<u8>(rng());

    Bytes b = a;
    for (std::size_t i = 100; i < 140; ++i) b[i] ^= 0xFF;   // small local edit

    Bytes c = a;
    c.insert(c.end(), 2000, 0x41);                          // appended data

    Bytes d(30000);
    for (u8& x : d) x = static_cast<u8>(rng());             // unrelated

    std::string ha = FuzzyHash::compute(ByteView(a.data(), a.size()));
    std::string hb = FuzzyHash::compute(ByteView(b.data(), b.size()));
    std::string hc = FuzzyHash::compute(ByteView(c.data(), c.size()));
    std::string hd = FuzzyHash::compute(ByteView(d.data(), d.size()));

    CHECK(!ha.empty());
    CHECK_EQ(FuzzyHash::compare(ha, ha), 100);
    CHECK(FuzzyHash::compare(ha, hb) > 80);
    CHECK(FuzzyHash::compare(ha, hc) > 80);
    // The property that matters: unrelated data must not look similar. An early
    // version of this scored ~50 here because the edit-distance substitution
    // cost was 1 instead of 2.
    CHECK(FuzzyHash::compare(ha, hd) < 20);
}

TEST("matcher: literals, offsets and overlaps") {
    Matcher m;
    CHECK(m.add(Pattern::fromLiteral(bv("he"), 1)));
    CHECK(m.add(Pattern::fromLiteral(bv("she"), 2)));
    CHECK(m.add(Pattern::fromLiteral(bv("his"), 3)));
    CHECK(m.add(Pattern::fromLiteral(bv("hers"), 4)));
    m.build();

    std::multiset<std::pair<u32, std::size_t>> hits;
    m.scan(bv("ushers"), [&](const Match& hit) {
        hits.emplace(hit.patternId, hit.offset);
        return true;
    });
    CHECK(hits.count({2, 1}) == 1);   // "she" at 1
    CHECK(hits.count({1, 2}) == 1);   // "he"  at 2
    CHECK(hits.count({4, 2}) == 1);   // "hers" at 2
    CHECK(hits.count({3, 0}) == 0);   // "his" absent
}

TEST("matcher: case-insensitive patterns") {
    Matcher m;
    CHECK(m.add(Pattern::fromLiteral(bv("kernel32"), 7, /*nocase=*/true)));
    m.build();
    int count = 0;
    m.scan(bv("KERNEL32.DLL and Kernel32.dll and kernel32"), [&](const Match&) {
        ++count;
        return true;
    });
    CHECK_EQ(count, 3);
}

TEST("matcher: wildcard patterns") {
    Matcher m;
    auto p = Pattern::fromHexPattern("64 8B ?? 30", 11);
    CHECK(p.has_value());
    if (p) CHECK(m.add(*p));
    m.build();

    Bytes data = {0x64, 0x8B, 0x40, 0x30, 0x00, 0x64, 0x8B, 0x45, 0x30};
    std::vector<std::size_t> offsets;
    m.scan(ByteView(data.data(), data.size()), [&](const Match& hit) {
        offsets.push_back(hit.offset);
        return true;
    });
    CHECK_EQ(offsets.size(), std::size_t(2));
    if (offsets.size() == 2) {
        CHECK_EQ(offsets[0], std::size_t(0));
        CHECK_EQ(offsets[1], std::size_t(5));
    }
}

TEST("matcher: early termination is honoured") {
    Matcher m;
    CHECK(m.add(Pattern::fromLiteral(bv("aa"), 1)));
    m.build();
    Bytes data(100, 'a');
    int   seen = 0;
    m.scan(ByteView(data.data(), data.size()), [&](const Match&) {
        ++seen;
        return false;   // stop after the first hit
    });
    CHECK_EQ(seen, 1);
}

TEST("matcher: differential fuzz against the naive reference") {
    std::mt19937 rng(20260809);
    std::size_t  totalMatches = 0;
    int          mismatches   = 0;

    for (int iteration = 0; iteration < 400; ++iteration) {
        // A small alphabet makes accidental matches, overlaps and shared
        // suffixes common — which is exactly where an automaton goes wrong.
        const int alphabet = 3 + static_cast<int>(rng() % 4);
        const int nPatterns = 1 + static_cast<int>(rng() % 8);

        std::vector<std::vector<int>> specs;
        std::vector<bool>             nocaseFlags;
        Matcher                       m;
        std::vector<u32>              ids;

        for (int p = 0; p < nPatterns; ++p) {
            const std::size_t len = 2 + rng() % 6;
            std::vector<int>  spec(len);
            for (std::size_t j = 0; j < len; ++j) {
                if (rng() % 8 == 0 && j != 0 && j + 1 != len)
                    spec[j] = -1;   // interior wildcard
                else
                    spec[j] = 'a' + static_cast<int>(rng() % alphabet);
            }
            bool nocase = (rng() % 4 == 0);
            auto pattern = Pattern::fromHexPattern(specToHex(spec), static_cast<u32>(p));
            if (!pattern) continue;
            pattern->nocase = nocase;
            if (!m.add(*pattern)) continue;
            specs.push_back(spec);
            nocaseFlags.push_back(nocase);
            ids.push_back(static_cast<u32>(p));
        }
        if (specs.empty()) continue;
        m.build();

        const std::size_t dataLen = 20 + rng() % 200;
        Bytes             data(dataLen);
        for (u8& b : data) {
            u8 c = static_cast<u8>('a' + rng() % alphabet);
            if (rng() % 6 == 0) c = static_cast<u8>(std::toupper(c));
            b = c;
        }

        std::multiset<std::pair<u32, std::size_t>> actual;
        m.scan(ByteView(data.data(), data.size()), [&](const Match& hit) {
            actual.emplace(hit.patternId, hit.offset);
            return true;
        });

        std::multiset<std::pair<u32, std::size_t>> expected;
        for (std::size_t p = 0; p < specs.size(); ++p)
            for (std::size_t off :
                 naiveFind(specs[p], ByteView(data.data(), data.size()), nocaseFlags[p]))
                expected.emplace(ids[p], off);

        totalMatches += expected.size();
        if (actual != expected) ++mismatches;
    }

    CHECK_EQ(mismatches, 0);
    CHECK(totalMatches > 500);   // the corpus must actually exercise the matcher
}
