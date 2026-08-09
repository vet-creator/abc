// SPDX-License-Identifier: MIT
#pragma once

#include <functional>
#include <string>
#include <vector>

#include "shiranui/common.hpp"

namespace shiranui::analysis {

// ---------------------------------------------------------------------------
// Statistical measures used by the heuristic engine
// ---------------------------------------------------------------------------

/// Shannon entropy in bits/byte, 0.0 .. 8.0.
double shannonEntropy(ByteView data);

/// Highest entropy found over any window of `window` bytes (packed-region hint).
double peakWindowEntropy(ByteView data, std::size_t window = 4096);

/// Chi-square statistic against a uniform byte distribution. Encrypted or
/// compressed data lands very low; natural text lands very high.
double chiSquareUniform(ByteView data);

/// Fraction of bytes that are printable ASCII or common whitespace.
double printableRatio(ByteView data);

/// Longest run of a single repeated byte, as a fraction of the total size.
double maxByteRunRatio(ByteView data);

/// True when the buffer looks like UTF-16LE text (used for script scanning).
bool looksLikeUtf16Le(ByteView data);

/// Extracts printable ASCII and UTF-16LE strings of at least `minLen`.
std::vector<std::string> extractStrings(ByteView data, std::size_t minLen = 6,
                                        std::size_t maxCount = 4096);

// ---------------------------------------------------------------------------
// Context-triggered piecewise hashing (fuzzy hash) for near-duplicate malware
// detection. Compatible in spirit with ssdeep; the digest format is
// "blocksize:hash1:hash2" and comparison yields a 0..100 similarity score.
// ---------------------------------------------------------------------------
class FuzzyHash {
public:
    static std::string compute(ByteView data);
    /// 0 (unrelated) .. 100 (identical). Returns 0 if block sizes are incomparable.
    static int compare(std::string_view a, std::string_view b);
};

// ---------------------------------------------------------------------------
// Aho-Corasick multi-pattern matcher with wildcard support.
//
// Patterns may contain wildcard bytes (YARA-style "??"). The longest literal
// run of each pattern is used as the automaton anchor; candidate hits are then
// verified against the full pattern. This keeps matching linear in the input
// while still supporting jokers, which a plain Aho-Corasick cannot express.
// ---------------------------------------------------------------------------
struct PatternToken {
    u8   value = 0;
    bool wildcard = false;
};

struct Pattern {
    std::vector<PatternToken> tokens;
    bool                      nocase = false;   ///< ASCII case-insensitive
    u32                       id     = 0;       ///< caller-defined identifier

    [[nodiscard]] std::size_t length() const { return tokens.size(); }
    /// Builds a pattern from literal bytes.
    static Pattern fromLiteral(ByteView bytes, u32 id, bool nocase = false);
    /// Builds a pattern from a hex string that may contain '??' wildcards.
    static std::optional<Pattern> fromHexPattern(std::string_view spec, u32 id);
};

struct Match {
    u32         patternId = 0;
    std::size_t offset    = 0;   ///< offset of the first byte of the match
};

class Matcher {
public:
    /// Adds a pattern. Must be called before build(). Returns false if the
    /// pattern has no literal anchor at all (e.g. entirely wildcards).
    bool add(Pattern pattern);

    /// Compiles the automaton. Idempotent.
    void build();

    [[nodiscard]] bool  empty() const noexcept { return patterns_.empty(); }
    [[nodiscard]] std::size_t patternCount() const noexcept { return patterns_.size(); }
    [[nodiscard]] std::size_t stateCount() const noexcept { return next_.size() / 256; }

    /// Scans `data`, invoking `sink` for every verified match. `sink` returns
    /// false to stop scanning early.
    void scan(ByteView data, const std::function<bool(const Match&)>& sink) const;

    /// Convenience wrapper collecting up to `limit` matches.
    [[nodiscard]] std::vector<Match> scanAll(ByteView data, std::size_t limit = 4096) const;

private:
    struct Anchor {
        u32         patternIndex = 0;
        std::size_t anchorOffset = 0;   ///< anchor start within the pattern
        std::size_t anchorLength = 0;
    };

    [[nodiscard]] bool verify(const Pattern& p, ByteView data, std::size_t start) const;

    std::vector<Pattern> patterns_;
    std::vector<Anchor>  anchors_;      ///< indexed by automaton output id
    std::vector<i32>     next_;         ///< 256-ary goto/transition table (flat)
    std::vector<i32>     fail_;
    std::vector<i32>     outputHead_;   ///< first *own* output id at this state, -1 if none
    std::vector<i32>     outputNext_;   ///< intrusive list of own output ids
    std::vector<i32>     outputAnchor_; ///< anchor index for each output id
    std::vector<i32>     dictLink_;     ///< nearest failure-ancestor carrying outputs
    bool                 built_ = false;
    bool                 anyNocase_ = false;
};

}  // namespace shiranui::analysis
