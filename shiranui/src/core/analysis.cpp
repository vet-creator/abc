// SPDX-License-Identifier: MIT
#include "shiranui/analysis.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace shiranui::analysis {

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------
double shannonEntropy(ByteView data) {
    if (data.empty()) return 0.0;
    u64 freq[256] = {0};
    for (u8 b : data) ++freq[b];
    const double n = static_cast<double>(data.size());
    double       h = 0.0;
    for (u64 f : freq) {
        if (!f) continue;
        double p = static_cast<double>(f) / n;
        h -= p * std::log2(p);
    }
    return h;
}

double peakWindowEntropy(ByteView data, std::size_t window) {
    if (data.empty()) return 0.0;
    if (data.size() <= window) return shannonEntropy(data);

    // Sliding window with an incrementally maintained histogram.
    u64    freq[256] = {0};
    double best      = 0.0;
    for (std::size_t i = 0; i < window; ++i) ++freq[data[i]];

    auto entropyOf = [&](std::size_t n) {
        double h  = 0.0;
        double nd = static_cast<double>(n);
        for (u64 f : freq) {
            if (!f) continue;
            double p = static_cast<double>(f) / nd;
            h -= p * std::log2(p);
        }
        return h;
    };

    best = entropyOf(window);
    const std::size_t step = std::max<std::size_t>(1, window / 4);
    for (std::size_t start = step; start + window <= data.size(); start += step) {
        for (std::size_t i = start - step; i < start; ++i) --freq[data[i]];
        for (std::size_t i = start + window - step; i < start + window; ++i) ++freq[data[i]];
        best = std::max(best, entropyOf(window));
    }
    return best;
}

double chiSquareUniform(ByteView data) {
    if (data.empty()) return 0.0;
    u64 freq[256] = {0};
    for (u8 b : data) ++freq[b];
    const double expect = static_cast<double>(data.size()) / 256.0;
    double       chi    = 0.0;
    for (u64 f : freq) {
        double d = static_cast<double>(f) - expect;
        chi += (d * d) / expect;
    }
    return chi;
}

double printableRatio(ByteView data) {
    if (data.empty()) return 0.0;
    std::size_t good = 0;
    for (u8 b : data)
        if ((b >= 0x20 && b <= 0x7e) || b == '\t' || b == '\n' || b == '\r') ++good;
    return static_cast<double>(good) / static_cast<double>(data.size());
}

double maxByteRunRatio(ByteView data) {
    if (data.empty()) return 0.0;
    std::size_t best = 1, run = 1;
    for (std::size_t i = 1; i < data.size(); ++i) {
        run  = (data[i] == data[i - 1]) ? run + 1 : 1;
        best = std::max(best, run);
    }
    return static_cast<double>(best) / static_cast<double>(data.size());
}

bool looksLikeUtf16Le(ByteView data) {
    if (data.size() < 8) return false;
    std::size_t probe = std::min<std::size_t>(data.size() & ~std::size_t{1}, 512);
    std::size_t zeroHigh = 0, pairs = 0;
    for (std::size_t i = 0; i + 1 < probe; i += 2) {
        ++pairs;
        if (data[i + 1] == 0 && data[i] >= 0x09) ++zeroHigh;
    }
    return pairs > 0 && static_cast<double>(zeroHigh) / static_cast<double>(pairs) > 0.85;
}

std::vector<std::string> extractStrings(ByteView data, std::size_t minLen, std::size_t maxCount) {
    std::vector<std::string> out;
    std::string              cur;
    auto flush = [&]() {
        if (cur.size() >= minLen && out.size() < maxCount) out.push_back(cur);
        cur.clear();
    };
    // ASCII pass
    for (u8 b : data) {
        if (b >= 0x20 && b <= 0x7e) {
            cur.push_back(static_cast<char>(b));
            if (cur.size() > 1024) flush();
        } else {
            flush();
            if (out.size() >= maxCount) return out;
        }
    }
    flush();
    // UTF-16LE pass (ASCII subset)
    cur.clear();
    for (std::size_t i = 0; i + 1 < data.size(); i += 2) {
        if (data[i] >= 0x20 && data[i] <= 0x7e && data[i + 1] == 0) {
            cur.push_back(static_cast<char>(data[i]));
            if (cur.size() > 1024) flush();
        } else {
            flush();
            if (out.size() >= maxCount) return out;
        }
    }
    flush();
    return out;
}

// ---------------------------------------------------------------------------
// Fuzzy hashing (CTPH)
// ---------------------------------------------------------------------------
namespace {

constexpr u32 kSpamSumLength = 64;
constexpr u32 kMinBlockSize  = 3;
const char*   kB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// ssdeep's rolling hash: three accumulators over a 7-byte window.
struct Roll {
    static constexpr u32 kWindow = 7;
    u8  win[kWindow] = {0};
    u32 h1 = 0, h2 = 0, h3 = 0, n = 0;

    u32 update(u8 c) {
        h2 -= h1;
        h2 += kWindow * c;
        h1 += c;
        h1 -= win[n % kWindow];
        win[n % kWindow] = c;
        ++n;
        h3 = (h3 << 5) & 0xFFFFFFFFu;
        h3 ^= c;
        return h1 + h2 + h3;
    }
};

inline u32 fnv(u32 h, u8 c) { return (h * 0x01000193u) ^ c; }

std::string spamsum(ByteView data, u32 blockSize, std::string& second) {
    Roll        roll;
    u32         h1 = 0x28021967u, h2 = 0x28021967u;
    std::string s1, s2;
    for (u8 c : data) {
        h1 = fnv(h1, c);
        h2 = fnv(h2, c);
        u32 r = roll.update(c);
        if (blockSize && (r % blockSize) == blockSize - 1) {
            if (s1.size() < kSpamSumLength - 1) {
                s1.push_back(kB64[h1 % 64]);
                h1 = 0x28021967u;
            }
        }
        if (blockSize && (r % (blockSize * 2)) == blockSize * 2 - 1) {
            if (s2.size() < kSpamSumLength / 2 - 1) {
                s2.push_back(kB64[h2 % 64]);
                h2 = 0x28021967u;
            }
        }
    }
    if (!data.empty()) {
        s1.push_back(kB64[h1 % 64]);
        s2.push_back(kB64[h2 % 64]);
    }
    second = s2;
    return s1;
}

/// Levenshtein distance with ssdeep's cost model: insert/delete = 1,
/// substitute = 2. The substitution cost is what makes unrelated digests score
/// near zero instead of near fifty.
int editDistance(std::string_view a, std::string_view b) {
    std::vector<int> prev(b.size() + 1), cur(b.size() + 1);
    for (std::size_t j = 0; j <= b.size(); ++j) prev[j] = static_cast<int>(j);
    for (std::size_t i = 1; i <= a.size(); ++i) {
        cur[0] = static_cast<int>(i);
        for (std::size_t j = 1; j <= b.size(); ++j) {
            int cost = (a[i - 1] == b[j - 1]) ? 0 : 2;
            cur[j]   = std::min({prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost});
        }
        prev.swap(cur);
    }
    return prev[b.size()];
}

/// Collapses runs of 4+ identical characters, as ssdeep does before comparison.
std::string eliminateRuns(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        std::size_t n = out.size();
        if (n >= 3 && out[n - 1] == c && out[n - 2] == c && out[n - 3] == c) continue;
        out.push_back(c);
    }
    return out;
}

/// ssdeep requires a shared substring of at least the rolling-window length
/// before two digests are considered comparable at all. Without this guard,
/// unrelated digests score ~15 instead of 0.
bool hasCommonSubstring(std::string_view a, std::string_view b, std::size_t n) {
    if (a.size() < n || b.size() < n) return false;
    for (std::size_t i = 0; i + n <= a.size(); ++i)
        if (b.find(a.substr(i, n)) != std::string_view::npos) return true;
    return false;
}

int scoreStrings(std::string_view a, std::string_view b, u32 blockSize) {
    std::string ea = eliminateRuns(a), eb = eliminateRuns(b);
    if (ea.empty() && eb.empty()) return 100;
    if (ea.empty() || eb.empty()) return 0;
    if (ea == eb) return 100;
    if (!hasCommonSubstring(ea, eb, Roll::kWindow)) return 0;
    int d = editDistance(ea, eb);
    // Normalise against the combined length, then scale as ssdeep does.
    int total = static_cast<int>(ea.size() + eb.size());
    int score = 100 - (100 * d) / std::max(1, total);
    // Small block sizes carry less evidence: cap the score accordingly.
    int cap = static_cast<int>(blockSize / kMinBlockSize * std::min(ea.size(), eb.size()));
    return std::max(0, std::min(score, cap > 100 ? 100 : cap));
}

}  // namespace

std::string FuzzyHash::compute(ByteView data) {
    u32 blockSize = kMinBlockSize;
    // Choose a block size so the signature lands near kSpamSumLength characters.
    while (blockSize * kSpamSumLength < data.size()) blockSize *= 2;

    std::string s2;
    std::string s1 = spamsum(data, blockSize, s2);
    while (blockSize > kMinBlockSize && s1.size() < kSpamSumLength / 2) {
        blockSize /= 2;
        s1 = spamsum(data, blockSize, s2);
    }
    return fmtU64(blockSize) + ":" + s1 + ":" + s2;
}

int FuzzyHash::compare(std::string_view a, std::string_view b) {
    auto parse = [](std::string_view s, u32& bs, std::string_view& p1, std::string_view& p2) {
        std::size_t c1 = s.find(':');
        if (c1 == std::string_view::npos) return false;
        std::size_t c2 = s.find(':', c1 + 1);
        if (c2 == std::string_view::npos) return false;
        bs = 0;
        for (std::size_t i = 0; i < c1; ++i) {
            if (s[i] < '0' || s[i] > '9') return false;
            bs = bs * 10 + static_cast<u32>(s[i] - '0');
        }
        p1 = s.substr(c1 + 1, c2 - c1 - 1);
        p2 = s.substr(c2 + 1);
        return bs != 0;
    };

    u32              ba = 0, bb = 0;
    std::string_view a1, a2, b1, b2;
    if (!parse(a, ba, a1, a2) || !parse(b, bb, b1, b2)) return 0;
    if (ba == bb) return std::max(scoreStrings(a1, b1, ba), scoreStrings(a2, b2, ba * 2));
    if (ba == bb * 2) return scoreStrings(a2, b1, bb);
    if (bb == ba * 2) return scoreStrings(a1, b2, ba);
    return 0;  // block sizes too far apart to compare meaningfully
}

// ---------------------------------------------------------------------------
// Pattern construction
// ---------------------------------------------------------------------------
Pattern Pattern::fromLiteral(ByteView bytes, u32 id, bool nocase) {
    Pattern p;
    p.id     = id;
    p.nocase = nocase;
    p.tokens.reserve(bytes.size());
    for (u8 b : bytes) p.tokens.push_back(PatternToken{b, false});
    return p;
}

std::optional<Pattern> Pattern::fromHexPattern(std::string_view spec, u32 id) {
    Pattern p;
    p.id = id;
    std::vector<char> nibbles;
    for (char c : spec) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '{' || c == '}') continue;
        nibbles.push_back(c);
    }
    if (nibbles.size() % 2 != 0) return std::nullopt;
    auto hexVal = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < nibbles.size(); i += 2) {
        char hi = nibbles[i], lo = nibbles[i + 1];
        if (hi == '?' && lo == '?') {
            p.tokens.push_back(PatternToken{0, true});
            continue;
        }
        int h = hexVal(hi), l = hexVal(lo);
        if (h < 0 || l < 0) return std::nullopt;   // half-wildcards unsupported
        p.tokens.push_back(PatternToken{static_cast<u8>((h << 4) | l), false});
    }
    if (p.tokens.empty()) return std::nullopt;
    return p;
}

// ---------------------------------------------------------------------------
// Aho-Corasick
// ---------------------------------------------------------------------------
namespace {
inline u8 foldByte(u8 b) { return (b >= 'A' && b <= 'Z') ? static_cast<u8>(b - 'A' + 'a') : b; }
}  // namespace

bool Matcher::add(Pattern pattern) {
    if (pattern.tokens.empty()) return false;

    // Locate the longest literal run to serve as the automaton anchor.
    std::size_t bestStart = 0, bestLen = 0, curStart = 0, curLen = 0;
    for (std::size_t i = 0; i < pattern.tokens.size(); ++i) {
        if (pattern.tokens[i].wildcard) {
            curLen = 0;
        } else {
            if (curLen == 0) curStart = i;
            ++curLen;
            if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
        }
    }
    if (bestLen == 0) return false;  // all wildcards: rejected

    if (pattern.nocase) anyNocase_ = true;
    built_ = false;
    patterns_.push_back(std::move(pattern));
    anchors_.push_back(Anchor{static_cast<u32>(patterns_.size() - 1), bestStart, bestLen});
    return true;
}

void Matcher::build() {
    if (built_) return;
    built_ = true;
    next_.assign(256, -1);
    fail_.assign(1, 0);
    outputHead_.assign(1, -1);
    dictLink_.assign(1, -1);
    outputNext_.clear();
    outputAnchor_.clear();

    auto newState = [&]() -> i32 {
        next_.insert(next_.end(), 256, -1);
        fail_.push_back(0);
        outputHead_.push_back(-1);
        dictLink_.push_back(-1);
        return static_cast<i32>(fail_.size()) - 1;
    };

    // Trie insertion of every anchor.
    for (std::size_t ai = 0; ai < anchors_.size(); ++ai) {
        const Anchor&  a = anchors_[ai];
        const Pattern& p = patterns_[a.patternIndex];
        i32            s = 0;
        for (std::size_t i = 0; i < a.anchorLength; ++i) {
            u8 b = p.tokens[a.anchorOffset + i].value;
            if (p.nocase) b = foldByte(b);
            // NOTE: newState() reallocates next_, so the slot must be re-indexed
            // after the call. Holding a reference across it is a dangling write.
            const std::size_t idx = static_cast<std::size_t>(s) * 256 + b;
            if (next_[idx] < 0) {
                i32 created = newState();
                next_[idx]  = created;
            }
            s = next_[idx];
        }
        i32 outId = static_cast<i32>(outputAnchor_.size());
        outputAnchor_.push_back(static_cast<i32>(ai));
        outputNext_.push_back(outputHead_[static_cast<std::size_t>(s)]);
        outputHead_[static_cast<std::size_t>(s)] = outId;
    }

    // BFS to build failure links and convert the trie into a full DFA.
    std::vector<i32> queue;
    queue.reserve(fail_.size());
    for (int c = 0; c < 256; ++c) {
        i32& slot = next_[static_cast<std::size_t>(c)];
        if (slot < 0) {
            slot = 0;
        } else {
            fail_[static_cast<std::size_t>(slot)] = 0;
            queue.push_back(slot);
        }
    }
    for (std::size_t qi = 0; qi < queue.size(); ++qi) {
        i32 s = queue[qi];
        i32 f = fail_[static_cast<std::size_t>(s)];
        // Dictionary link: nearest state along the failure chain that carries
        // outputs. Computed rather than spliced, so no output list is ever
        // mutated after creation (splicing corrupts shared suffix chains).
        dictLink_[static_cast<std::size_t>(s)] =
            (outputHead_[static_cast<std::size_t>(f)] >= 0) ? f
                                                            : dictLink_[static_cast<std::size_t>(f)];
        for (int c = 0; c < 256; ++c) {
            i32& slot = next_[static_cast<std::size_t>(s) * 256 + static_cast<std::size_t>(c)];
            i32  via  = next_[static_cast<std::size_t>(f) * 256 + static_cast<std::size_t>(c)];
            if (slot < 0) {
                slot = via;
            } else {
                fail_[static_cast<std::size_t>(slot)] = via;
                queue.push_back(slot);
            }
        }
    }
}

bool Matcher::verify(const Pattern& p, ByteView data, std::size_t start) const {
    if (start + p.tokens.size() > data.size()) return false;
    for (std::size_t i = 0; i < p.tokens.size(); ++i) {
        const PatternToken& t = p.tokens[i];
        if (t.wildcard) continue;
        u8 a = data[start + i], b = t.value;
        if (p.nocase) { a = foldByte(a); b = foldByte(b); }
        if (a != b) return false;
    }
    return true;
}

void Matcher::scan(ByteView data, const std::function<bool(const Match&)>& sink) const {
    if (!built_ || data.empty() || anchors_.empty()) return;

    // Two passes are needed when case-insensitive patterns exist: the automaton
    // is built over folded bytes, so the input must be folded to match. Rather
    // than allocating a folded copy, fold on the fly and verify exactly.
    i32 stateExact = 0;
    i32 stateFold  = 0;
    for (std::size_t i = 0; i < data.size(); ++i) {
        u8 b = data[i];
        stateExact = next_[static_cast<std::size_t>(stateExact) * 256 + b];
        if (anyNocase_) {
            u8 fb    = foldByte(b);
            stateFold = next_[static_cast<std::size_t>(stateFold) * 256 + fb];
        }

        for (int pass = 0; pass < (anyNocase_ ? 2 : 1); ++pass) {
            i32 entry = (pass == 0) ? stateExact : stateFold;
            for (i32 st = (outputHead_[static_cast<std::size_t>(entry)] >= 0)
                              ? entry
                              : dictLink_[static_cast<std::size_t>(entry)];
                 st >= 0; st = dictLink_[static_cast<std::size_t>(st)]) {
                for (i32 out = outputHead_[static_cast<std::size_t>(st)]; out >= 0;
                     out     = outputNext_[static_cast<std::size_t>(out)]) {
                    const Anchor& a =
                        anchors_[static_cast<std::size_t>(outputAnchor_[static_cast<std::size_t>(out)])];
                    const Pattern& p = patterns_[a.patternIndex];
                    if (p.nocase != (pass == 1)) continue;

                    std::size_t anchorEnd   = i + 1;                // exclusive
                    std::size_t anchorStart = anchorEnd - a.anchorLength;
                    if (anchorStart < a.anchorOffset) continue;     // would start before byte 0
                    std::size_t patStart = anchorStart - a.anchorOffset;
                    if (!verify(p, data, patStart)) continue;
                    if (!sink(Match{p.id, patStart})) return;
                }
            }
        }
    }
}

std::vector<Match> Matcher::scanAll(ByteView data, std::size_t limit) const {
    std::vector<Match> out;
    scan(data, [&](const Match& m) {
        out.push_back(m);
        return out.size() < limit;
    });
    return out;
}

}  // namespace shiranui::analysis
