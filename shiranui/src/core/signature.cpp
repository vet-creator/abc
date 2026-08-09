// SPDX-License-Identifier: MIT
#include "shiranui/signature.hpp"

#include <cctype>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>

namespace shiranui::sig {

namespace {

// ---------------------------------------------------------------------------
// Condition tokenizer
// ---------------------------------------------------------------------------
struct Token {
    enum class Kind { End, Ident, Number, Dollar, LParen, RParen, Op } kind = Kind::End;
    std::string text;
    u64         number = 0;
};

class Lexer {
public:
    explicit Lexer(std::string_view s) : s_(s) {}

    Token next() {
        skipSpace();
        Token t;
        if (pos_ >= s_.size()) return t;
        char c = s_[pos_];
        if (c == '(') { ++pos_; t.kind = Token::Kind::LParen; return t; }
        if (c == ')') { ++pos_; t.kind = Token::Kind::RParen; return t; }
        if (c == '<' || c == '>' || c == '=') {
            ++pos_;
            t.kind = Token::Kind::Op;
            t.text = std::string(1, c);
            if (pos_ < s_.size() && s_[pos_] == '=') ++pos_;  // accept <=, >=, ==
            return t;
        }
        if (c == '$') {
            std::size_t start = pos_++;
            while (pos_ < s_.size() && (isIdentChar(s_[pos_]) || s_[pos_] == '*')) ++pos_;
            t.kind = Token::Kind::Dollar;
            t.text = std::string(s_.substr(start, pos_ - start));
            return t;
        }
        if (c >= '0' && c <= '9') {
            std::size_t start = pos_;
            while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') ++pos_;
            u64 v = 0;
            for (std::size_t i = start; i < pos_; ++i) v = v * 10 + static_cast<u64>(s_[i] - '0');
            // size suffixes
            if (pos_ < s_.size()) {
                char sfx = static_cast<char>(std::tolower(static_cast<unsigned char>(s_[pos_])));
                if (sfx == 'k') { v *= 1024; ++pos_; }
                else if (sfx == 'm') { v *= 1024ull * 1024; ++pos_; }
                if (pos_ < s_.size() &&
                    std::tolower(static_cast<unsigned char>(s_[pos_])) == 'b')
                    ++pos_;
            }
            t.kind   = Token::Kind::Number;
            t.number = v;
            return t;
        }
        if (isIdentChar(c)) {
            std::size_t start = pos_;
            while (pos_ < s_.size() && isIdentChar(s_[pos_])) ++pos_;
            t.kind = Token::Kind::Ident;
            t.text = toLowerAscii(s_.substr(start, pos_ - start));
            return t;
        }
        ++pos_;  // skip anything unrecognised
        return next();
    }

    [[nodiscard]] std::size_t position() const { return pos_; }
    void                      rewind(std::size_t p) { pos_ = p; }

private:
    static bool isIdentChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '_' || c == '.';
    }
    void skipSpace() {
        while (pos_ < s_.size() &&
               (s_[pos_] == ' ' || s_[pos_] == '\t' || s_[pos_] == '\n' || s_[pos_] == '\r'))
            ++pos_;
    }

    std::string_view s_;
    std::size_t      pos_ = 0;
};

// ---------------------------------------------------------------------------
// Recursive-descent condition parser
// ---------------------------------------------------------------------------
class CondParser {
public:
    CondParser(std::string_view text, const std::vector<StringDef>& strings)
        : lex_(text), strings_(strings) {
        advance();
    }

    Result<Cond> parse() {
        Result<Cond> r = parseOr();
        if (!r) return r;
        if (cur_.kind != Token::Kind::End)
            return Result<Cond>::fail("unexpected trailing token in condition");
        return r;
    }

private:
    void advance() {
        prevPos_ = lex_.position();
        cur_     = lex_.next();
    }

    Result<Cond> parseOr() {
        Result<Cond> left = parseAnd();
        if (!left) return left;
        while (cur_.kind == Token::Kind::Ident && cur_.text == "or") {
            advance();
            Result<Cond> right = parseAnd();
            if (!right) return right;
            Cond node;
            node.kind = Cond::Kind::Or;
            node.children.push_back(std::move(*left));
            node.children.push_back(std::move(*right));
            left = Result<Cond>(std::move(node));
        }
        return left;
    }

    Result<Cond> parseAnd() {
        Result<Cond> left = parseNot();
        if (!left) return left;
        while (cur_.kind == Token::Kind::Ident && cur_.text == "and") {
            advance();
            Result<Cond> right = parseNot();
            if (!right) return right;
            Cond node;
            node.kind = Cond::Kind::And;
            node.children.push_back(std::move(*left));
            node.children.push_back(std::move(*right));
            left = Result<Cond>(std::move(node));
        }
        return left;
    }

    Result<Cond> parseNot() {
        if (cur_.kind == Token::Kind::Ident && cur_.text == "not") {
            advance();
            Result<Cond> inner = parseNot();
            if (!inner) return inner;
            Cond node;
            node.kind = Cond::Kind::Not;
            node.children.push_back(std::move(*inner));
            return Result<Cond>(std::move(node));
        }
        return parsePrimary();
    }

    /// Consumes an optional "of them" / "of ($a,$b)" tail.
    void consumeOfThem() {
        if (cur_.kind == Token::Kind::Ident && cur_.text == "of") {
            advance();
            if (cur_.kind == Token::Kind::Ident && cur_.text == "them") advance();
        }
    }

    Result<Cond> parsePrimary() {
        if (cur_.kind == Token::Kind::LParen) {
            advance();
            Result<Cond> inner = parseOr();
            if (!inner) return inner;
            if (cur_.kind != Token::Kind::RParen)
                return Result<Cond>::fail("unbalanced parenthesis in condition");
            advance();
            return inner;
        }
        if (cur_.kind == Token::Kind::Dollar) {
            std::string id = cur_.text;
            advance();
            Cond node;
            if (id == "$*") {
                node.kind = Cond::Kind::NOfThem;
                node.n    = 1;
                return Result<Cond>(std::move(node));
            }
            int idx = -1;
            for (std::size_t i = 0; i < strings_.size(); ++i)
                if (strings_[i].id == id) { idx = static_cast<int>(i); break; }
            if (idx < 0) return Result<Cond>::fail("condition references undefined string " + id);
            node.kind        = Cond::Kind::StringRef;
            node.stringIndex = idx;
            return Result<Cond>(std::move(node));
        }
        if (cur_.kind == Token::Kind::Number) {
            u64 n = cur_.number;
            advance();
            consumeOfThem();
            Cond node;
            node.kind = Cond::Kind::NOfThem;
            node.n    = static_cast<int>(n);
            return Result<Cond>(std::move(node));
        }
        if (cur_.kind == Token::Kind::Ident) {
            std::string kw = cur_.text;
            advance();
            if (kw == "all") {
                consumeOfThem();
                Cond node;
                node.kind = Cond::Kind::NOfThem;
                node.n    = static_cast<int>(strings_.size());
                return Result<Cond>(std::move(node));
            }
            if (kw == "any") {
                consumeOfThem();
                Cond node;
                node.kind = Cond::Kind::NOfThem;
                node.n    = 1;
                return Result<Cond>(std::move(node));
            }
            if (kw == "none") {
                consumeOfThem();
                Cond inner;
                inner.kind = Cond::Kind::NOfThem;
                inner.n    = 1;
                Cond node;
                node.kind = Cond::Kind::Not;
                node.children.push_back(std::move(inner));
                return Result<Cond>(std::move(node));
            }
            if (kw == "true")  { Cond n; n.kind = Cond::Kind::True; return Result<Cond>(std::move(n)); }
            if (kw == "false") {
                Cond t; t.kind = Cond::Kind::True;
                Cond n; n.kind = Cond::Kind::Not; n.children.push_back(std::move(t));
                return Result<Cond>(std::move(n));
            }
            if (kw == "filesize") {
                if (cur_.kind != Token::Kind::Op)
                    return Result<Cond>::fail("expected a comparison operator after 'filesize'");
                char op = cur_.text[0];
                advance();
                if (cur_.kind != Token::Kind::Number)
                    return Result<Cond>::fail("expected a number after 'filesize' comparison");
                Cond node;
                node.kind     = Cond::Kind::FileSizeCmp;
                node.cmpOp    = op;
                node.cmpValue = cur_.number;
                advance();
                return Result<Cond>(std::move(node));
            }
            return Result<Cond>::fail("unknown keyword '" + kw + "' in condition");
        }
        return Result<Cond>::fail("empty or malformed condition");
    }

    Lexer                        lex_;
    const std::vector<StringDef>& strings_;
    Token                        cur_;
    std::size_t                  prevPos_ = 0;
};

/// Unescapes a double-quoted rule string literal.
std::optional<Bytes> unescapeLiteral(std::string_view body) {
    Bytes out;
    for (std::size_t i = 0; i < body.size(); ++i) {
        char c = body[i];
        if (c != '\\') { out.push_back(static_cast<u8>(c)); continue; }
        if (++i >= body.size()) return std::nullopt;
        switch (body[i]) {
            case 'n':  out.push_back('\n'); break;
            case 'r':  out.push_back('\r'); break;
            case 't':  out.push_back('\t'); break;
            case '0':  out.push_back(0); break;
            case '\\': out.push_back('\\'); break;
            case '"':  out.push_back('"'); break;
            case 'x': {
                if (i + 2 >= body.size()) return std::nullopt;
                auto b = fromHex(body.substr(i + 1, 2));
                if (!b || b->size() != 1) return std::nullopt;
                out.push_back((*b)[0]);
                i += 2;
                break;
            }
            default: return std::nullopt;
        }
    }
    return out;
}

std::string previewOf(ByteView data) {
    std::string s;
    for (std::size_t i = 0; i < data.size() && i < 40; ++i) {
        u8 b = data[i];
        s += (b >= 0x20 && b <= 0x7e) ? static_cast<char>(b) : '.';
    }
    if (data.size() > 40) s += "...";
    return s;
}

}  // namespace

// ---------------------------------------------------------------------------
// Condition evaluation
// ---------------------------------------------------------------------------
bool evaluateCondition(const Cond& c, const std::vector<bool>& matched, u64 fileSize) {
    switch (c.kind) {
        case Cond::Kind::True: return true;
        case Cond::Kind::StringRef:
            return c.stringIndex >= 0 && static_cast<std::size_t>(c.stringIndex) < matched.size() &&
                   matched[static_cast<std::size_t>(c.stringIndex)];
        case Cond::Kind::NOfThem: {
            int count = 0;
            for (bool m : matched)
                if (m) ++count;
            return count >= c.n;
        }
        case Cond::Kind::And:
            for (const Cond& ch : c.children)
                if (!evaluateCondition(ch, matched, fileSize)) return false;
            return true;
        case Cond::Kind::Or:
            for (const Cond& ch : c.children)
                if (evaluateCondition(ch, matched, fileSize)) return true;
            return false;
        case Cond::Kind::Not:
            return c.children.empty() || !evaluateCondition(c.children[0], matched, fileSize);
        case Cond::Kind::FileSizeCmp:
            if (c.cmpOp == '<') return fileSize < c.cmpValue;
            if (c.cmpOp == '>') return fileSize > c.cmpValue;
            return fileSize == c.cmpValue;
    }
    return false;
}

Result<Cond> parseCondition(std::string_view text, const std::vector<StringDef>& strings) {
    CondParser p(text, strings);
    return p.parse();
}

// ---------------------------------------------------------------------------
// Rule file parsing
// ---------------------------------------------------------------------------
namespace {


}  // namespace

Status RuleSet::parseHashLine(std::string_view line, std::string_view sourceName, u32 lineNo) {
    // hash sha256 = <hex> name=Foo severity=critical family=Bar
    // hash imphash = <hex> name=Foo
    std::vector<std::string> toks = split(line, ' ');
    std::string              kind, value;
    HashEntry                entry;
    entry.severity = Severity::Critical;

    std::string joined = std::string(line);
    // Normalise "a = b" into "a=b" so a single tokenizer pass works.
    std::string norm;
    for (std::size_t i = 0; i < joined.size(); ++i) {
        if (joined[i] == '=') {
            while (!norm.empty() && norm.back() == ' ') norm.pop_back();
            norm.push_back('=');
            while (i + 1 < joined.size() && joined[i + 1] == ' ') ++i;
        } else {
            norm.push_back(joined[i]);
        }
    }
    for (const std::string& t : split(norm, ' ')) {
        if (t == "hash") continue;
        std::size_t eq = t.find('=');
        if (eq == std::string::npos) continue;
        std::string k = toLowerAscii(t.substr(0, eq));
        std::string v = t.substr(eq + 1);
        if (!v.empty() && v.front() == '"' && v.back() == '"' && v.size() >= 2)
            v = v.substr(1, v.size() - 2);
        if (k == "sha256" || k == "imphash") { kind = k; value = toLowerAscii(v); }
        else if (k == "name") entry.name = v;
        else if (k == "family") entry.family = v;
        else if (k == "severity") {
            auto s = severityFromName(v);
            if (s) entry.severity = *s;
        }
    }
    if (kind.empty() || value.empty())
        return Status::fail(std::string(sourceName) + ":" + fmtU64(lineNo) + ": malformed hash line");
    if (kind == "sha256" && value.size() != 64)
        return Status::fail(std::string(sourceName) + ":" + fmtU64(lineNo) +
                            ": sha256 must be 64 hex characters");
    if (entry.name.empty()) entry.name = kind + ":" + value.substr(0, 12);
    if (kind == "sha256") sha256Set_[value] = entry;
    else                  imphashSet_[value] = entry;
    return Status::success();
}


namespace {

/// Rewrites rule text into one logical element per line.
///
/// The rest of the parser is line-oriented, which is easy to reason about but
/// would otherwise reject `rule R { strings: $a = "x" condition: $a }` -- a form
/// people write constantly. Rather than scatter "is it on this line?" checks
/// through the parser, normalisation happens once, here, with full awareness of
/// string literals and hex blocks so that a brace, a '#' or a '$' appearing
/// inside a literal is never mistaken for structure.
template <class Line>
std::vector<Line> splitLogicalLines(std::string_view text) {
    std::vector<Line> out;
    std::string       cur;
    u32               lineNo = 1, curLine = 1;
    bool              insideRule = false, inString = false, inHex = false;
    int               section = 0;   // 0 none, 1 meta, 2 strings, 3 condition

    auto flush = [&] {
        std::string_view t = trim(cur);
        if (!t.empty()) out.push_back(Line{std::string(t), curLine});
        cur.clear();
        curLine = lineNo;
    };
    auto emit = [&](const char* literal) {
        out.push_back(Line{std::string(literal), lineNo});
        curLine = lineNo;
    };
    auto keywordAt = [&](std::size_t pos, std::string_view kw) {
        if (text.size() - pos < kw.size()) return false;
        if (text.compare(pos, kw.size(), kw) != 0) return false;
        if (pos > 0) {
            char p = text[pos - 1];
            if (std::isalnum(static_cast<unsigned char>(p)) || p == '_' || p == '$') return false;
        }
        return true;
    };

    for (std::size_t i = 0; i < text.size(); ++i) {
        char c = text[i];
        if (c == '\r') continue;
        if (c == '\n') {
            flush();
            ++lineNo;
            curLine = lineNo;
            continue;
        }

        if (inString) {
            cur.push_back(c);
            if (c == '\\' && i + 1 < text.size()) { cur.push_back(text[++i]); continue; }
            if (c == '"') inString = false;
            continue;
        }
        if (inHex) {
            cur.push_back(c);
            if (c == '}') inHex = false;
            continue;
        }
        if (c == '"') { inString = true; cur.push_back(c); continue; }
        if (c == '#' || (c == '/' && i + 1 < text.size() && text[i + 1] == '/')) {
            while (i < text.size() && text[i] != '\n') ++i;
            --i;   // let the newline branch handle the break
            continue;
        }

        if (!insideRule) {
            cur.push_back(c);
            if (c == '{') { insideRule = true; section = 0; flush(); }
            continue;
        }

        if (c == '}') { flush(); emit("}"); insideRule = false; section = 0; continue; }
        if (c == '{') { inHex = true; cur.push_back(c); continue; }

        if (keywordAt(i, "meta:"))      { flush(); emit("meta:");      section = 1; i += 4; continue; }
        if (keywordAt(i, "strings:"))   { flush(); emit("strings:");   section = 2; i += 7; continue; }
        if (keywordAt(i, "condition:")) { flush(); emit("condition:"); section = 3; i += 9; continue; }

        // A '$' inside the strings section starts a new definition once the
        // current fragment already holds a complete one. Conditions are left
        // alone: "$a and $b" is a single expression, not two definitions.
        if (section == 2 && c == '$' && cur.find('=') != std::string::npos) flush();
        cur.push_back(c);
    }
    flush();
    return out;
}

}  // namespace

Status RuleSet::parseText(std::string_view text, std::string_view sourceName) {
    std::vector<SourceLine> lines = splitLogicalLines<SourceLine>(text);

    for (std::size_t i = 0; i < lines.size();) {
        std::string_view t = trim(lines[i].text);
        if (t.empty()) { ++i; continue; }

        if (startsWith(t, "hash ")) {
            Status s = parseHashLine(t, sourceName, lines[i].line);
            if (!s) return s;
            ++i;
            continue;
        }
        if (startsWith(t, "rule ")) {
            Status s = parseRule(lines, i, sourceName);
            if (!s) return s;
            continue;
        }
        return Status::fail(std::string(sourceName) + ":" + fmtU64(lines[i].line) +
                            ": expected 'rule' or 'hash', got '" + std::string(t.substr(0, 24)) + "'");
    }
    compiled_ = false;
    return Status::success();
}

Status RuleSet::parseRule(const std::vector<SourceLine>& lines, std::size_t& i,
                          std::string_view sourceName) {
    const u32 startLine = lines[i].line;
    auto err = [&](const std::string& m) {
        return Status::fail(std::string(sourceName) + ":" + fmtU64(startLine) + ": " + m);
    };

    Rule rule;
    rule.sourceFile = std::string(sourceName);
    rule.sourceLine = startLine;

    std::string header = std::string(trim(lines[i].text));
    // rule NAME [: tag tag] {
    std::size_t brace = header.find('{');
    std::string decl  = header.substr(5, brace == std::string::npos ? std::string::npos : brace - 5);
    std::size_t colon = decl.find(':');
    if (colon != std::string::npos) {
        for (const std::string& tg : split(decl.substr(colon + 1), ' ')) rule.tags.push_back(tg);
        decl = decl.substr(0, colon);
    }
    rule.name = std::string(trim(decl));
    if (rule.name.empty()) return err("rule has no name");
    if (brace == std::string::npos) return err("expected '{' on the rule line");
    ++i;

    std::string section;
    std::string conditionText;
    bool        closed = false;
    for (; i < lines.size(); ++i) {
        std::string_view t = trim(lines[i].text);
        if (t.empty()) continue;
        if (t == "}") { ++i; closed = true; break; }

        if (t == "meta:" || t == "strings:" || t == "condition:") {
            section = std::string(t.substr(0, t.size() - 1));
            continue;
        }

        if (section == "meta") {
            std::size_t eq = t.find('=');
            if (eq == std::string::npos) continue;
            std::string k = toLowerAscii(std::string(trim(t.substr(0, eq))));
            std::string v = std::string(trim(t.substr(eq + 1)));
            if (v.size() >= 2 && v.front() == '"' && v.back() == '"') v = v.substr(1, v.size() - 2);
            if (k == "severity") {
                auto s = severityFromName(v);
                if (!s) return err("unknown severity '" + v + "'");
                rule.severity = *s;
            } else if (k == "family")      rule.family = v;
            else if (k == "description")   rule.description = v;
            else if (k == "reference")     rule.reference = v;
            else if (k == "enabled")       rule.enabled = !(v == "false" || v == "0" || v == "no");
        } else if (section == "strings") {
            if (t.empty() || t[0] != '$') return err("string definition must start with '$'");
            std::size_t eq = t.find('=');
            if (eq == std::string::npos) return err("string definition needs '='");
            StringDef def;
            def.id = std::string(trim(t.substr(0, eq)));
            std::string_view rhs = trim(t.substr(eq + 1));
            if (rhs.empty()) return err("empty string definition for " + def.id);

            Bytes literal;
            if (rhs.front() == '{') {
                std::size_t close = rhs.find('}');
                if (close == std::string_view::npos) return err("unterminated hex string " + def.id);
                def.isHex = true;
                auto pat  = analysis::Pattern::fromHexPattern(rhs.substr(1, close - 1), 0);
                if (!pat) return err("malformed hex string " + def.id);
                def.preview = std::string(trim(rhs.substr(0, close + 1)));
                rule.strings.push_back(std::move(def));
                // Hex patterns are registered later, during compile().
                rule.strings.back().patternIds.clear();
                // Stash the raw text so compile() can rebuild it.
                rule.strings.back().preview = std::string(rhs.substr(0, close + 1));
                continue;
            }
            if (rhs.front() != '"') return err("string " + def.id + " must be quoted or hex");
            std::size_t close = std::string_view::npos;
            for (std::size_t k = 1; k < rhs.size(); ++k) {
                if (rhs[k] == '"' && rhs[k - 1] != '\\') { close = k; break; }
            }
            if (close == std::string_view::npos) return err("unterminated string " + def.id);
            auto body = unescapeLiteral(rhs.substr(1, close - 1));
            if (!body) return err("bad escape sequence in " + def.id);
            literal = *body;
            if (literal.empty()) return err("string " + def.id + " is empty");

            std::string mods = toLowerAscii(rhs.substr(close + 1));
            def.nocase = mods.find("nocase") != std::string::npos;
            def.wide   = mods.find("wide") != std::string::npos;
            def.ascii  = !def.wide || mods.find("ascii") != std::string::npos;
            def.preview = previewOf(ByteView(literal.data(), literal.size()));
            // Encode the literal into preview-independent storage via hex text so
            // compile() has a single code path for both string kinds.
            def.isHex = false;
            rule.strings.push_back(def);
            rawLiterals_.push_back(std::move(literal));
            rule.strings.back().patternIds.push_back(
                static_cast<u32>(rawLiterals_.size() - 1) | 0x8000'0000u);
        } else if (section == "condition") {
            if (!conditionText.empty()) conditionText += " ";
            conditionText += std::string(t);
        } else {
            return err("content outside of meta/strings/condition sections");
        }
    }

    // Both of these were silently tolerated once: an unterminated rule simply ran
    // to end of file, and a missing condition defaulted to "any of them". Either
    // one turns a typo into a rule that does not do what its author believes.
    if (!closed) return err("rule '" + rule.name + "' is missing its closing '}'");
    if (conditionText.empty()) return err("rule '" + rule.name + "' has no condition");

    auto cond = parseCondition(conditionText, rule.strings);
    if (!cond) return err(cond.error());
    rule.condition = std::move(*cond);

    rules_.push_back(std::move(rule));
    return Status::success();
}

Status RuleSet::loadFile(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return Status::fail("cannot open rule file: " + pathToUtf8(path));
    std::ostringstream ss;
    ss << f.rdbuf();
    return parseText(ss.str(), pathToUtf8(path.filename()));
}

Status RuleSet::loadDirectory(const fs::path& dir) {
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) return Status::fail("not a directory: " + pathToUtf8(dir));
    std::size_t loaded = 0;
    for (const auto& e : fs::directory_iterator(dir, ec)) {
        if (!e.is_regular_file(ec)) continue;
        if (e.path().extension() != ".srules") continue;
        Status s = loadFile(e.path());
        if (!s) return s;
        ++loaded;
    }
    if (loaded == 0) return Status::fail("no .srules files found in " + pathToUtf8(dir));
    return Status::success();
}

void RuleSet::compile() {
    if (compiled_) return;
    matcher_ = analysis::Matcher{};
    patternOwners_.clear();

    for (std::size_t ri = 0; ri < rules_.size(); ++ri) {
        Rule& rule = rules_[ri];
        if (!rule.enabled) continue;
        for (std::size_t si = 0; si < rule.strings.size(); ++si) {
            StringDef&       def = rule.strings[si];
            std::vector<u32> encoded = def.patternIds;
            def.patternIds.clear();

            auto registerPattern = [&](analysis::Pattern p) {
                u32 id = static_cast<u32>(patternOwners_.size());
                p.id   = id;
                if (matcher_.add(std::move(p))) {
                    patternOwners_.push_back(PatternOwner{static_cast<u32>(ri), static_cast<u32>(si)});
                    def.patternIds.push_back(id);
                }
            };

            if (def.isHex) {
                auto pat = analysis::Pattern::fromHexPattern(def.preview, 0);
                if (pat) registerPattern(std::move(*pat));
                continue;
            }
            if (encoded.empty()) continue;
            std::size_t idx = encoded[0] & 0x7fff'ffffu;
            if (idx >= rawLiterals_.size()) continue;
            const Bytes& lit = rawLiterals_[idx];

            if (def.ascii)
                registerPattern(analysis::Pattern::fromLiteral(ByteView(lit.data(), lit.size()), 0,
                                                               def.nocase));
            if (def.wide) {
                Bytes w;
                w.reserve(lit.size() * 2);
                for (u8 b : lit) { w.push_back(b); w.push_back(0); }
                registerPattern(analysis::Pattern::fromLiteral(ByteView(w.data(), w.size()), 0,
                                                               def.nocase));
            }
        }
    }
    matcher_.build();
    compiled_ = true;
}

std::vector<RuleHit> RuleSet::scan(ByteView data) const {
    std::vector<RuleHit> hits;
    if (!compiled_ || rules_.empty()) return hits;

    // matchedByRule[rule][stringIndex] = matched, plus the first offset seen.
    std::vector<std::vector<bool>> matchedByRule(rules_.size());
    std::vector<u64>               firstOffset(rules_.size(), 0);
    std::vector<bool>              ruleTouched(rules_.size(), false);
    for (std::size_t i = 0; i < rules_.size(); ++i)
        matchedByRule[i].assign(rules_[i].strings.size(), false);

    matcher_.scan(data, [&](const analysis::Match& m) {
        if (m.patternId >= patternOwners_.size()) return true;
        const PatternOwner& owner = patternOwners_[m.patternId];
        auto& flags = matchedByRule[owner.ruleIndex];
        if (owner.stringIndex < flags.size()) {
            if (!flags[owner.stringIndex]) {
                flags[owner.stringIndex] = true;
                if (!ruleTouched[owner.ruleIndex]) {
                    ruleTouched[owner.ruleIndex] = true;
                    firstOffset[owner.ruleIndex] = m.offset;
                }
            }
        }
        return true;
    });

    for (std::size_t ri = 0; ri < rules_.size(); ++ri) {
        const Rule& rule = rules_[ri];
        if (!rule.enabled) continue;
        if (!evaluateCondition(rule.condition, matchedByRule[ri], data.size())) continue;
        RuleHit hit;
        hit.rule        = &rule;
        hit.firstOffset = firstOffset[ri];
        for (std::size_t si = 0; si < rule.strings.size(); ++si)
            if (matchedByRule[ri][si]) hit.matchedStrings.push_back(rule.strings[si].id);
        hits.push_back(std::move(hit));
    }
    return hits;
}

const RuleSet::HashEntry* RuleSet::lookupSha256(const std::string& hexLower) const {
    auto it = sha256Set_.find(hexLower);
    return it == sha256Set_.end() ? nullptr : &it->second;
}

const RuleSet::HashEntry* RuleSet::lookupImphash(const std::string& hexLower) const {
    auto it = imphashSet_.find(hexLower);
    return it == imphashSet_.end() ? nullptr : &it->second;
}

}  // namespace shiranui::sig
