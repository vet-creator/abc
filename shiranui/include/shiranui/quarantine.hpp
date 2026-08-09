// SPDX-License-Identifier: MIT
// Encrypted quarantine store.
//
// A quarantined file is moved into an AES-256-GCM container so it can no longer
// be executed or opened by other software, while remaining fully recoverable.
// The container header is authenticated (it is the AEAD's associated data), so
// tampering with the recorded origin path or hash is detected on restore.
//
// Container layout:
//   0   4   magic "SHQ1"
//   4   2   format version (little endian)
//   6   2   header length H (includes these 8 bytes)
//   8  H-8  header JSON, authenticated as AAD
//   H   12  nonce
//  H+12 16  GCM tag
//  H+28  N  ciphertext
#pragma once

#include <string>
#include <vector>

#include "shiranui/common.hpp"
#include "shiranui/verdict.hpp"

namespace shiranui {

struct QuarantineRecord {
    std::string id;               ///< opaque identifier (hex)
    fs::path    originalPath;
    u64         originalSize = 0;
    std::string sha256;
    std::string detectionName;
    Severity    severity = Severity::Medium;
    u64         quarantinedAtMs = 0;
    fs::path    containerPath;

    [[nodiscard]] std::string toJson() const;
};

class Quarantine {
public:
    /// Default store location: %ProgramData%\Shiranui\quarantine on Windows,
    /// $XDG_DATA_HOME/shiranui/quarantine elsewhere.
    static fs::path defaultRoot();

    explicit Quarantine(fs::path root);

    /// Creates the store and loads (or generates) the master key.
    Status open();

    /// Moves `path` into the store. On success the original file is removed.
    Result<QuarantineRecord> quarantineFile(const fs::path& path, const FileVerdict& verdict);

    /// Lists every record currently held.
    [[nodiscard]] std::vector<QuarantineRecord> list() const;

    /// Restores a record. `destination` empty means the original location.
    /// Verifies both the AEAD tag and the recorded SHA-256 before writing.
    Status restore(const std::string& id, const fs::path& destination = {});

    /// Irreversibly removes a record (container is shredded).
    Status purge(const std::string& id);
    Status purgeAll();

    [[nodiscard]] const fs::path& root() const { return root_; }

private:
    [[nodiscard]] fs::path keyPath() const { return root_ / "master.key"; }
    Status                 loadOrCreateKey();
    /// Per-item key = HMAC-SHA256(master, "shiranui-quarantine-v1" || id).
    [[nodiscard]] std::array<u8, 32> deriveItemKey(const std::string& id) const;
    [[nodiscard]] Result<QuarantineRecord> readRecord(const fs::path& container) const;

    fs::path            root_;
    std::array<u8, 32>  masterKey_{};
    bool                opened_ = false;
};

}  // namespace shiranui
