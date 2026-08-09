// SPDX-License-Identifier: MIT
#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "shiranui/common.hpp"
#include "shiranui/signature.hpp"
#include "shiranui/verdict.hpp"

namespace shiranui {

struct ScanOptions {
    u64  maxFileSize     = 256ull * 1024 * 1024;  ///< larger files are hashed only
    u64  deepScanLimit   = 64ull * 1024 * 1024;   ///< content scanned up to this many bytes
    bool followSymlinks  = false;                 ///< off by default: reparse loops are a DoS
    bool computeFuzzyHash = true;
    bool verifySignatures = true;                 ///< Authenticode (Windows only)
    bool skipKnownGoodSigned = false;             ///< fast path for signed OS binaries
    unsigned threads      = 0;                    ///< 0 = std::thread::hardware_concurrency()
    std::vector<std::string> excludeGlobs;
    std::vector<std::string> includeExtensions;   ///< empty = every extension
    HeuristicConfig          heuristics;
};

struct ScanStats {
    std::atomic<u64> filesSeen{0};
    std::atomic<u64> filesScanned{0};
    std::atomic<u64> filesSkipped{0};
    std::atomic<u64> bytesScanned{0};
    std::atomic<u64> errors{0};
    std::atomic<u64> malicious{0};
    std::atomic<u64> suspicious{0};
    std::atomic<u64> directories{0};
    u64              elapsedMs = 0;

    [[nodiscard]] std::string summary() const;
};

/// Multi-threaded recursive scanner. Directory traversal happens on the calling
/// thread; file analysis is distributed across a worker pool. Results are
/// delivered through `onResult`, serialised by an internal mutex so callers do
/// not need their own locking.
class ScanEngine {
public:
    using ResultCallback   = std::function<void(const FileVerdict&)>;
    using ProgressCallback = std::function<void(const ScanStats&, const fs::path& current)>;

    ScanEngine(const sig::RuleSet& rules, ScanOptions options);
    ~ScanEngine();

    ScanEngine(const ScanEngine&)            = delete;
    ScanEngine& operator=(const ScanEngine&) = delete;

    /// Analyses a single file. Safe to call concurrently.
    [[nodiscard]] FileVerdict scanFile(const fs::path& path) const;

    /// Recursively scans `root` (a file or directory).
    void scanPath(const fs::path& root, const ResultCallback& onResult, ScanStats& stats,
                  const ProgressCallback& onProgress = {});

    /// Requests cancellation; in-flight files finish, no new work is started.
    void cancel() noexcept { cancelled_.store(true, std::memory_order_relaxed); }
    [[nodiscard]] bool cancelled() const noexcept { return cancelled_.load(std::memory_order_relaxed); }

    [[nodiscard]] const ScanOptions& options() const noexcept { return options_; }

private:
    [[nodiscard]] bool shouldSkip(const fs::path& path) const;

    const sig::RuleSet& rules_;
    ScanOptions         options_;
    HeuristicEngine     heuristics_;
    std::atomic<bool>   cancelled_{false};
};

}  // namespace shiranui
