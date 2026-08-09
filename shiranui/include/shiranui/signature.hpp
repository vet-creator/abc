// SPDX-License-Identifier: MIT
// Rule engine: a compact, YARA-inspired signature language.
//
// A rule file is plain UTF-8 text. Example:
//
//   rule Example_Dropper : dropper win32 {
//       meta:
//           severity    = high
//           family      = "Example"
//           description = "Writes a payload to %TEMP% and executes it"
//       strings:
//           $a = "cmd.exe /c start" nocase
//           $b = { 4D 5A ?? ?? 00 00 }
//           $c = "GetTempPathW" ascii wide
//       condition:
//           $b and 2 of them
//   }
//
//   hash sha256 = 275a02...fd0f name=EICAR severity=critical
//
// All strings across all rules are compiled into a single Aho-Corasick
// automaton, so scan cost is O(input) regardless of the rule count.
#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "shiranui/analysis.hpp"
#include "shiranui/common.hpp"
#include "shiranui/verdict.hpp"

namespace shiranui::sig {

/// Condition AST. std::vector of an incomplete type is well-defined since C++17.
struct Cond {
    enum class Kind {
        True,
        StringRef,     ///< a specific $id matched
        NOfThem,       ///< at least `n` distinct strings matched
        And,
        Or,
        Not,
        FileSizeCmp,   ///< filesize <op> value
    };

    Kind              kind = Kind::True;
    std::vector<Cond> children;
    int               stringIndex = -1;   ///< index into Rule::strings
    int               n           = 0;
    char              cmpOp       = '<';  ///< '<' '>' '='
    u64               cmpValue    = 0;
};

struct StringDef {
    std::string      id;             ///< including the leading '$'
    std::vector<u32> patternIds;     ///< global pattern ids in the shared matcher
    bool             isHex   = false;
    bool             nocase  = false;
    bool             wide    = false;
    bool             ascii   = true;
    std::string      preview;        ///< short human-readable form for reports
};

struct Rule {
    std::string              name;
    std::vector<std::string> tags;
    Severity                 severity = Severity::Medium;
    std::string              family;
    std::string              description;
    std::string              reference;
    std::vector<StringDef>   strings;
    Cond                     condition;
    std::string              sourceFile;
    u32                      sourceLine = 0;
    bool                     enabled    = true;
};

struct RuleHit {
    const Rule*              rule = nullptr;
    std::vector<std::string> matchedStrings;
    u64                      firstOffset = 0;
};

class RuleSet {
public:
    /// Parses rule text. On failure, returns the offending line in the message.
    Status parseText(std::string_view text, std::string_view sourceName);
    Status loadFile(const fs::path& path);
    /// Loads every *.srules file in a directory (non-recursive).
    Status loadDirectory(const fs::path& dir);

    /// Compiles all string patterns into the shared automaton. Must be called
    /// after loading and before scanning.
    void compile();

    [[nodiscard]] std::size_t ruleCount() const { return rules_.size(); }
    [[nodiscard]] std::size_t hashCount() const { return sha256Set_.size(); }
    [[nodiscard]] std::size_t patternCount() const { return matcher_.patternCount(); }
    [[nodiscard]] const std::vector<Rule>& rules() const { return rules_; }

    /// Content scan. `data` may be a whole file or a decoded region.
    [[nodiscard]] std::vector<RuleHit> scan(ByteView data) const;

    /// Exact-hash lookup. Returns the associated label, or nullptr.
    struct HashEntry {
        std::string name;
        Severity    severity = Severity::Critical;
        std::string family;
    };
    [[nodiscard]] const HashEntry* lookupSha256(const std::string& hexLower) const;
    [[nodiscard]] const HashEntry* lookupImphash(const std::string& hexLower) const;

private:
    struct PatternOwner {
        u32 ruleIndex   = 0;
        u32 stringIndex = 0;
    };

    /// One logical unit of rule text plus the physical line it came from, so a
    /// rule written entirely on one line still reports a useful location.
    struct SourceLine {
        std::string text;
        u32         line = 0;
    };

    Status parseRule(const std::vector<SourceLine>& lines, std::size_t& i,
                     std::string_view sourceName);
    Status parseHashLine(std::string_view line, std::string_view sourceName, u32 lineNo);

    std::vector<Rule>                            rules_;
    std::vector<Bytes>                           rawLiterals_;
    std::vector<PatternOwner>                    patternOwners_;
    analysis::Matcher                            matcher_;
    std::unordered_map<std::string, HashEntry>   sha256Set_;
    std::unordered_map<std::string, HashEntry>   imphashSet_;
    bool                                         compiled_ = false;
};

/// Evaluates a compiled condition against the set of matched string indices.
bool evaluateCondition(const Cond& c, const std::vector<bool>& matched, u64 fileSize);

/// Parses a condition expression. Exposed for unit testing.
Result<Cond> parseCondition(std::string_view text, const std::vector<StringDef>& strings);

}  // namespace shiranui::sig
