// SPDX-License-Identifier: MIT
#include "harness.hpp"

#include "shiranui/scanner.hpp"
#include "shiranui/signature.hpp"

using namespace shiranui;

namespace {

ByteView bv(std::string_view s) {
    return ByteView(reinterpret_cast<const u8*>(s.data()), s.size());
}

sig::RuleSet compile(std::string_view text) {
    sig::RuleSet set;
    Status       s = set.parseText(text, "inline");
    if (!s) std::printf("\n  rule parse failed: %s\n", s.message.c_str());
    set.compile();
    return set;
}

bool fired(const sig::RuleSet& set, std::string_view data, std::string_view ruleName) {
    for (const sig::RuleHit& hit : set.scan(bv(data)))
        if (hit.rule && hit.rule->name == ruleName) return true;
    return false;
}

}  // namespace

TEST("rule parsing: metadata, tags and severity") {
    auto set = compile(R"(
rule Sample_Rule : tag_one tag_two {
    meta:
        severity    = critical
        family      = "TestFamily"
        description = "A description"
    strings:
        $a = "needle"
    condition:
        $a
}
)");
    CHECK_EQ(set.ruleCount(), std::size_t(1));
    if (set.ruleCount() == 1) {
        const sig::Rule& r = set.rules().front();
        CHECK_EQ(r.name, std::string("Sample_Rule"));
        CHECK(r.severity == Severity::Critical);
        CHECK_EQ(r.family, std::string("TestFamily"));
        CHECK_EQ(r.tags.size(), std::size_t(2));
    }
    CHECK(fired(set, "a haystack with a needle inside", "Sample_Rule"));
    CHECK(!fired(set, "a haystack with nothing", "Sample_Rule"));
}

TEST("condition: boolean operators and precedence") {
    auto set = compile(R"(
rule And_Rule { strings: $a = "alpha"  $b = "beta"  condition: $a and $b }
rule Or_Rule  { strings: $a = "gamma"  $b = "delta" condition: $a or $b }
rule Not_Rule { strings: $a = "epsilon" $b = "zeta" condition: $a and not $b }
rule Prec_Rule { strings: $a = "p" $b = "q" $c = "r" condition: $a or $b and $c }
)");
    CHECK_EQ(set.ruleCount(), std::size_t(4));

    CHECK(fired(set, "alpha beta", "And_Rule"));
    CHECK(!fired(set, "alpha only", "And_Rule"));

    CHECK(fired(set, "gamma", "Or_Rule"));
    CHECK(fired(set, "delta", "Or_Rule"));

    CHECK(fired(set, "epsilon", "Not_Rule"));
    CHECK(!fired(set, "epsilon zeta", "Not_Rule"));

    // "and" binds tighter than "or": $a alone is sufficient.
    CHECK(fired(set, "p", "Prec_Rule"));
    CHECK(!fired(set, "q", "Prec_Rule"));
    CHECK(fired(set, "q r", "Prec_Rule"));
}

TEST("condition: parentheses override precedence") {
    auto set = compile(R"(
rule Paren_Rule { strings: $a = "p" $b = "q" $c = "r" condition: ($a or $b) and $c }
)");
    CHECK(!fired(set, "p", "Paren_Rule"));
    CHECK(fired(set, "p r", "Paren_Rule"));
    CHECK(fired(set, "q r", "Paren_Rule"));
}

TEST("condition: counting quantifiers") {
    auto set = compile(R"(
rule Two_Of { strings: $a = "aa" $b = "bb" $c = "cc" condition: 2 of them }
rule All_Of { strings: $a = "xx" $b = "yy" condition: all of them }
rule Any_Of { strings: $a = "mm" $b = "nn" condition: any of them }
rule None_Of { strings: $a = "oo" condition: none of them }
)");
    CHECK(!fired(set, "aa", "Two_Of"));
    CHECK(fired(set, "aa bb", "Two_Of"));
    CHECK(fired(set, "aa bb cc", "Two_Of"));
    // Two occurrences of the same string are not two distinct strings.
    CHECK(!fired(set, "aa aa aa", "Two_Of"));

    CHECK(!fired(set, "xx", "All_Of"));
    CHECK(fired(set, "xx yy", "All_Of"));
    CHECK(fired(set, "mm", "Any_Of"));
    CHECK(fired(set, "nothing here", "None_Of"));
    CHECK(!fired(set, "oo", "None_Of"));
}

TEST("condition: filesize comparison") {
    auto set = compile(R"(
rule Small_Only { strings: $a = "marker" condition: $a and filesize < 32 }
rule Large_Only { strings: $a = "marker" condition: $a and filesize > 32 }
)");
    CHECK(fired(set, "marker", "Small_Only"));
    CHECK(!fired(set, "marker", "Large_Only"));

    std::string big = "marker" + std::string(200, '.');
    CHECK(!fired(set, big, "Small_Only"));
    CHECK(fired(set, big, "Large_Only"));
}

TEST("string modifiers: nocase, wide and hex") {
    auto set = compile(R"(
rule NoCase { strings: $a = "MixedCase" nocase condition: $a }
rule Cased  { strings: $a = "MixedCase" condition: $a }
rule Wide   { strings: $a = "WideOnly" wide condition: $a }
rule Hexed  { strings: $a = { DE AD ?? EF } condition: $a }
)");
    CHECK(fired(set, "mixedcase", "NoCase"));
    CHECK(fired(set, "MIXEDCASE", "NoCase"));
    CHECK(!fired(set, "mixedcase", "Cased"));
    CHECK(fired(set, "MixedCase", "Cased"));

    std::string wide;
    for (char c : std::string("padding WideOnly padding")) {
        wide.push_back(c);
        wide.push_back('\0');
    }
    CHECK(fired(set, wide, "Wide"));
    CHECK(!fired(set, "WideOnly", "Wide"));

    std::string hexData("\xDE\xAD\x00\xEF", 4);
    CHECK(fired(set, hexData, "Hexed"));
    std::string hexOther("\xDE\xAD\x99\xEF", 4);
    CHECK(fired(set, hexOther, "Hexed"));
    std::string hexMiss("\xDE\xAD\x00\xEE", 4);
    CHECK(!fired(set, hexMiss, "Hexed"));
}

TEST("escape sequences in string literals") {
    auto set = compile(R"(
rule Escapes { strings: $a = "line\nbreak" $b = "tab\there" $c = "hex\x41char" condition: any of them }
)");
    CHECK(fired(set, "line\nbreak", "Escapes"));
    CHECK(fired(set, "tab\there", "Escapes"));
    CHECK(fired(set, "hexAchar", "Escapes"));
}

TEST("comments are ignored outside string literals") {
    auto set = compile(R"(
# a full-line comment
rule Commented {          // trailing comment
    strings:
        $a = "value # not a comment"
    condition:
        $a               # another comment
}
)");
    CHECK_EQ(set.ruleCount(), std::size_t(1));
    CHECK(fired(set, "value # not a comment", "Commented"));
}

TEST("malformed rules are reported, not silently accepted") {
    sig::RuleSet set;
    Status       s = set.parseText("rule Broken { condition: $missing }", "inline");
    CHECK(!s.ok);

    sig::RuleSet set2;
    Status       s2 = set2.parseText("rule Unclosed { strings: $a = \"x\" condition: $a", "inline");
    CHECK(!s2.ok);
}

TEST("hash entries are looked up exactly") {
    auto set = compile(
        "hash sha256 = 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f "
        "name=EICAR.Test severity=critical family=EICAR\n");
    CHECK_EQ(set.hashCount(), std::size_t(1));
    const auto* hit =
        set.lookupSha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    CHECK(hit != nullptr);
    if (hit) {
        CHECK_EQ(hit->name, std::string("EICAR.Test"));
        CHECK(hit->severity == Severity::Critical);
    }
    CHECK(set.lookupSha256("0000000000000000000000000000000000000000000000000000000000000000") ==
          nullptr);
}

TEST("EICAR is detected by the shipped rule shape") {
    auto set = compile(R"(
rule Eicar {
    meta:
        severity = critical
    strings:
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D }
    condition:
        $eicar
}
)");
    const char* kEicar =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    CHECK(fired(set, kEicar, "Eicar"));
    CHECK(fired(set, std::string("prefix ") + kEicar + " suffix", "Eicar"));
    CHECK(!fired(set, "a benign file about antivirus software", "Eicar"));
}

TEST("scanning is linear: many rules do not change the result") {
    std::string text;
    for (int i = 0; i < 200; ++i)
        text += "rule Filler_" + std::to_string(i) + " { strings: $a = \"zzz" +
                std::to_string(i) + "\" condition: $a }\n";
    text += "rule Target { strings: $a = \"the-needle\" condition: $a }\n";

    auto set = compile(text);
    CHECK_EQ(set.ruleCount(), std::size_t(201));
    CHECK(fired(set, "haystack the-needle haystack", "Target"));

    auto hits = set.scan(bv("haystack the-needle haystack"));
    CHECK_EQ(hits.size(), std::size_t(1));
}

TEST("heuristic thresholds map scores onto dispositions") {
    HeuristicConfig cfg;
    CHECK(cfg.suspiciousThreshold < cfg.maliciousThreshold);

    FileVerdict clean;
    clean.size = 100;
    HeuristicEngine engine(cfg);
    Bytes           benign(100, 'A');
    engine.evaluate(clean, ByteView(benign.data(), benign.size()));
    CHECK(clean.disposition == Disposition::Clean);
    CHECK(clean.score < cfg.suspiciousThreshold);
}

TEST("severity names round-trip") {
    for (Severity s : {Severity::Info, Severity::Low, Severity::Medium, Severity::High,
                       Severity::Critical}) {
        auto parsed = severityFromName(severityName(s));
        CHECK(parsed.has_value());
        if (parsed) CHECK(*parsed == s);
    }
    CHECK(!severityFromName("not-a-severity").has_value());
}

TEST("verdict JSON is well formed and escapes paths") {
    FileVerdict v;
    v.path        = utf8ToPath("C:\\dir\\with \"quotes\".exe");
    v.size        = 1234;
    v.sha256      = "ab";
    v.disposition = Disposition::Malicious;
    v.score       = 91.5;
    v.detections.push_back({"signature", "Rule_Name", "desc\nline", Severity::High, 40.0, 16, {}});

    std::string json = v.toJson();
    CHECK(json.front() == '{');
    CHECK(json.back() == '}');
    CHECK(json.find("\\\"quotes\\\"") != std::string::npos);
    CHECK(json.find("desc\\nline") != std::string::npos);
    // Balanced braces is a cheap structural check that catches truncation.
    int depth = 0;
    bool inString = false;
    for (std::size_t i = 0; i < json.size(); ++i) {
        char c = json[i];
        if (inString) {
            if (c == '\\') { ++i; continue; }
            if (c == '"') inString = false;
            continue;
        }
        if (c == '"') inString = true;
        else if (c == '{' || c == '[') ++depth;
        else if (c == '}' || c == ']') --depth;
    }
    CHECK_EQ(depth, 0);
    CHECK(!inString);
}
