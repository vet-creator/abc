// SPDX-License-Identifier: MIT
#include "shiranui/quarantine.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#include "shiranui/crypto.hpp"
#include "shiranui/platform.hpp"

namespace shiranui {

namespace {

constexpr u16 kFormatVersion = 1;
constexpr const char* kKdfLabel = "shiranui-quarantine-v1";

std::string jsonField(std::string_view json, std::string_view key) {
    std::string needle = "\"" + std::string(key) + "\":";
    std::size_t at     = json.find(needle);
    if (at == std::string_view::npos) return {};
    at += needle.size();
    while (at < json.size() && (json[at] == ' ')) ++at;
    if (at >= json.size()) return {};
    if (json[at] == '"') {
        ++at;
        std::string out;
        while (at < json.size() && json[at] != '"') {
            if (json[at] == '\\' && at + 1 < json.size()) {
                ++at;
                switch (json[at]) {
                    case 'n': out.push_back('\n'); break;
                    case 't': out.push_back('\t'); break;
                    case 'r': out.push_back('\r'); break;
                    default:  out.push_back(json[at]);
                }
            } else {
                out.push_back(json[at]);
            }
            ++at;
        }
        return out;
    }
    std::string out;
    while (at < json.size() && json[at] != ',' && json[at] != '}') out.push_back(json[at++]);
    return std::string(trim(out));
}

Status writeAll(const fs::path& p, ByteView data) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f) return Status::fail("cannot create " + pathToUtf8(p));
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!f) return Status::fail("write failed for " + pathToUtf8(p));
    return Status::success();
}

}  // namespace

std::string QuarantineRecord::toJson() const {
    std::ostringstream o;
    o << "{\"id\":\"" << jsonEscape(id) << "\""
      << ",\"original_path\":\"" << jsonEscape(pathToUtf8(originalPath)) << "\""
      << ",\"original_size\":" << originalSize
      << ",\"sha256\":\"" << sha256 << "\""
      << ",\"detection\":\"" << jsonEscape(detectionName) << "\""
      << ",\"severity\":\"" << severityName(severity) << "\""
      << ",\"quarantined_at\":\"" << isoTimestamp(quarantinedAtMs) << "\""
      << ",\"quarantined_at_ms\":" << quarantinedAtMs << "}";
    return o.str();
}

fs::path Quarantine::defaultRoot() {
#ifdef _WIN32
    if (const char* pd = std::getenv("ProgramData"))
        return utf8ToPath(pd) / "Shiranui" / "quarantine";
    return fs::path(L"C:\\ProgramData\\Shiranui\\quarantine");
#else
    if (const char* xdg = std::getenv("XDG_DATA_HOME"))
        return fs::path(xdg) / "shiranui" / "quarantine";
    if (const char* home = std::getenv("HOME"))
        return fs::path(home) / ".local" / "share" / "shiranui" / "quarantine";
    return fs::path("/tmp/shiranui-quarantine");
#endif
}

Quarantine::Quarantine(fs::path root) : root_(std::move(root)) {}

Status Quarantine::open() {
    std::error_code ec;
    fs::create_directories(root_, ec);
    if (ec) return Status::fail("cannot create quarantine directory: " + ec.message());
    Status s = loadOrCreateKey();
    if (!s) return s;
    opened_ = true;
    return Status::success();
}

Status Quarantine::loadOrCreateKey() {
    std::error_code ec;
    if (fs::exists(keyPath(), ec)) {
        auto mapped = MappedFile::open(keyPath());
        if (!mapped) return Status::fail("cannot read master key: " + mapped.error());
        if (mapped->size() != masterKey_.size())
            return Status::fail("master key file is corrupt (unexpected length)");
        std::memcpy(masterKey_.data(), mapped->data(), masterKey_.size());
        return Status::success();
    }
    Bytes key;
    try {
        key = crypto::randomBytes(masterKey_.size());
    } catch (const std::exception& e) {
        return Status::fail(std::string("cannot generate master key: ") + e.what());
    }
    std::memcpy(masterKey_.data(), key.data(), masterKey_.size());
    Status s = writeAll(keyPath(), ByteView(key.data(), key.size()));
    secureZero(key.data(), key.size());
    if (!s) return s;
#ifndef _WIN32
    fs::permissions(keyPath(), fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace, ec);
#endif
    return Status::success();
}

std::array<u8, 32> Quarantine::deriveItemKey(const std::string& id) const {
    std::string info = std::string(kKdfLabel) + id;
    return crypto::hmacSha256(ByteView(masterKey_.data(), masterKey_.size()),
                              ByteView(reinterpret_cast<const u8*>(info.data()), info.size()));
}

Result<QuarantineRecord> Quarantine::quarantineFile(const fs::path& path,
                                                    const FileVerdict& verdict) {
    if (!opened_) return Result<QuarantineRecord>::fail("quarantine store is not open");

    auto mapped = MappedFile::open(path);
    if (!mapped) return Result<QuarantineRecord>::fail("cannot read file: " + mapped.error());
    ByteView content = mapped->view();

    QuarantineRecord rec;
    Bytes            idBytes;
    try {
        idBytes = crypto::randomBytes(16);
    } catch (const std::exception& e) {
        return Result<QuarantineRecord>::fail(std::string("CSPRNG unavailable: ") + e.what());
    }
    rec.id              = toHex(ByteView(idBytes.data(), idBytes.size()));
    rec.originalPath    = fs::absolute(path);
    rec.originalSize    = content.size();
    rec.sha256          = verdict.sha256.empty() ? crypto::Sha256::hex(content) : verdict.sha256;
    rec.severity        = verdict.maxSeverity();
    rec.quarantinedAtMs = epochMillis();
    rec.detectionName   = verdict.detections.empty() ? "manual" : verdict.detections.front().name;
    rec.containerPath   = root_ / (rec.id + ".shq");

    std::string header = rec.toJson();
    if (header.size() + 8 > 0xFFFF)
        return Result<QuarantineRecord>::fail("quarantine header too large");

    Bytes blob;
    const u16 headerLen = static_cast<u16>(header.size() + 8);
    blob.push_back('S'); blob.push_back('H'); blob.push_back('Q'); blob.push_back('1');
    blob.push_back(static_cast<u8>(kFormatVersion)); blob.push_back(static_cast<u8>(kFormatVersion >> 8));
    blob.push_back(static_cast<u8>(headerLen)); blob.push_back(static_cast<u8>(headerLen >> 8));
    blob.insert(blob.end(), header.begin(), header.end());

    ByteView aad(blob.data(), blob.size());

    crypto::aead::Key   key{};
    auto                derived = deriveItemKey(rec.id);
    std::memcpy(key.data(), derived.data(), key.size());
    crypto::aead::Nonce nonce{};
    try {
        Bytes n = crypto::randomBytes(nonce.size());
        std::memcpy(nonce.data(), n.data(), nonce.size());
    } catch (const std::exception& e) {
        return Result<QuarantineRecord>::fail(std::string("CSPRNG unavailable: ") + e.what());
    }

    Bytes             cipher;
    crypto::aead::Tag tag{};
    crypto::aead::seal(key, nonce, aad, content, cipher, tag);
    secureZero(key.data(), key.size());
    secureZero(derived.data(), derived.size());

    blob.insert(blob.end(), nonce.begin(), nonce.end());
    blob.insert(blob.end(), tag.begin(), tag.end());
    blob.insert(blob.end(), cipher.begin(), cipher.end());

    Status s = writeAll(rec.containerPath, ByteView(blob.data(), blob.size()));
    if (!s) return Result<QuarantineRecord>::fail(s.message);

    mapped->close();   // release the mapping before deleting the original
    Status del = platform::shredFile(path, 1);
    if (!del) {
        std::error_code ec;
        fs::remove(rec.containerPath, ec);
        return Result<QuarantineRecord>::fail("could not remove the original file: " + del.message);
    }
    return rec;
}

Result<QuarantineRecord> Quarantine::readRecord(const fs::path& container) const {
    auto mapped = MappedFile::open(container, 64 * 1024);
    if (!mapped) return Result<QuarantineRecord>::fail(mapped.error());
    ByteView d = mapped->view();
    if (d.size() < 8 || d[0] != 'S' || d[1] != 'H' || d[2] != 'Q' || d[3] != '1')
        return Result<QuarantineRecord>::fail("not a quarantine container");
    u16 headerLen = static_cast<u16>(d[6] | (d[7] << 8));
    if (headerLen < 8 || headerLen > d.size())
        return Result<QuarantineRecord>::fail("corrupt container header");

    std::string json(reinterpret_cast<const char*>(d.data() + 8), headerLen - 8);
    QuarantineRecord rec;
    rec.id            = jsonField(json, "id");
    rec.originalPath  = utf8ToPath(jsonField(json, "original_path"));
    rec.sha256        = jsonField(json, "sha256");
    rec.detectionName = jsonField(json, "detection");
    rec.containerPath = container;
    std::string size  = jsonField(json, "original_size");
    rec.originalSize  = size.empty() ? 0 : std::strtoull(size.c_str(), nullptr, 10);
    std::string at    = jsonField(json, "quarantined_at_ms");
    rec.quarantinedAtMs = at.empty() ? 0 : std::strtoull(at.c_str(), nullptr, 10);
    auto sev = severityFromName(jsonField(json, "severity"));
    if (sev) rec.severity = *sev;
    return rec;
}

std::vector<QuarantineRecord> Quarantine::list() const {
    std::vector<QuarantineRecord> out;
    std::error_code               ec;
    if (!fs::is_directory(root_, ec)) return out;
    for (const auto& e : fs::directory_iterator(root_, ec)) {
        if (!e.is_regular_file(ec)) continue;
        if (e.path().extension() != ".shq") continue;
        auto rec = readRecord(e.path());
        if (rec) out.push_back(*rec);
    }
    std::sort(out.begin(), out.end(), [](const QuarantineRecord& a, const QuarantineRecord& b) {
        return a.quarantinedAtMs > b.quarantinedAtMs;
    });
    return out;
}

Status Quarantine::restore(const std::string& id, const fs::path& destination) {
    if (!opened_) return Status::fail("quarantine store is not open");
    fs::path container = root_ / (id + ".shq");
    std::error_code ec;
    if (!fs::exists(container, ec)) return Status::fail("no such quarantine id: " + id);

    auto mapped = MappedFile::open(container);
    if (!mapped) return Status::fail(mapped.error());
    ByteView d = mapped->view();
    if (d.size() < 8) return Status::fail("container truncated");
    u16 headerLen = static_cast<u16>(d[6] | (d[7] << 8));
    if (headerLen < 8 || static_cast<std::size_t>(headerLen) + 28 > d.size())
        return Status::fail("container truncated");

    auto rec = readRecord(container);
    if (!rec) return Status::fail(rec.error());

    ByteView aad = d.subspan(0, headerLen);
    crypto::aead::Nonce nonce{};
    crypto::aead::Tag   tag{};
    std::memcpy(nonce.data(), d.data() + headerLen, nonce.size());
    std::memcpy(tag.data(), d.data() + headerLen + nonce.size(), tag.size());
    ByteView cipher = d.subspan(static_cast<std::size_t>(headerLen) + 28);

    crypto::aead::Key key{};
    auto              derived = deriveItemKey(id);
    std::memcpy(key.data(), derived.data(), key.size());

    Bytes plain;
    bool  ok = crypto::aead::open(key, nonce, aad, cipher, tag, plain);
    secureZero(key.data(), key.size());
    secureZero(derived.data(), derived.size());
    if (!ok)
        return Status::fail("authentication failed: the container or its metadata was modified");

    std::string actual = crypto::Sha256::hex(ByteView(plain.data(), plain.size()));
    if (!rec->sha256.empty() && actual != rec->sha256)
        return Status::fail("restored content does not match the recorded SHA-256");

    fs::path target = destination.empty() ? rec->originalPath : destination;
    if (fs::is_directory(target, ec)) target /= rec->originalPath.filename();
    if (fs::exists(target, ec)) return Status::fail("refusing to overwrite " + pathToUtf8(target));
    fs::create_directories(target.parent_path(), ec);

    Status s = writeAll(target, ByteView(plain.data(), plain.size()));
    secureZero(plain.data(), plain.size());
    if (!s) return s;

    mapped->close();
    fs::remove(container, ec);
    return Status::success();
}

Status Quarantine::purge(const std::string& id) {
    fs::path container = root_ / (id + ".shq");
    std::error_code ec;
    if (!fs::exists(container, ec)) return Status::fail("no such quarantine id: " + id);
    return platform::shredFile(container, 1);
}

Status Quarantine::purgeAll() {
    std::size_t failures = 0;
    for (const QuarantineRecord& r : list())
        if (!purge(r.id)) ++failures;
    if (failures) return Status::fail(fmtU64(failures) + " item(s) could not be purged");
    return Status::success();
}

}  // namespace shiranui
