// SPDX-License-Identifier: MIT
#pragma once

#include <string>
#include <vector>

#include "shiranui/common.hpp"
#include "shiranui/pe.hpp"

namespace shiranui {

enum class Severity { Info = 0, Low, Medium, High, Critical };

std::string_view severityName(Severity s);
std::optional<Severity> severityFromName(std::string_view s);

enum class Disposition {
    Clean = 0,       ///< nothing of interest
    Suspicious,      ///< heuristics fired, no signature match
    Malicious,       ///< a signature or a decisive heuristic combination matched
    Error            ///< the file could not be examined
};

std::string_view dispositionName(Disposition d);

/// A single reason contributing to a verdict.
struct Detection {
    std::string source;        ///< "signature", "heuristic", "hash", "authenticode"
    std::string name;          ///< rule name or heuristic identifier
    std::string description;
    Severity    severity = Severity::Info;
    double      weight   = 0.0;     ///< contribution to the heuristic score
    u64         offset   = 0;       ///< byte offset where applicable
    std::vector<std::string> matchedStrings;
};

struct FileVerdict {
    fs::path    path;
    u64         size = 0;
    Disposition disposition = Disposition::Clean;
    double      score = 0.0;        ///< 0..100 heuristic confidence
    std::string sha256;
    std::string fuzzyHash;
    std::string error;

    bool        isPe = false;
    pe::Info    peInfo;

    /// Authenticode result (Windows only; unset elsewhere).
    bool        signatureChecked = false;
    bool        signatureValid   = false;
    std::string signerName;
    std::string signatureStatus;

    std::vector<Detection> detections;

    [[nodiscard]] Severity maxSeverity() const;
    [[nodiscard]] std::string toJson() const;
    /// Single-line human summary used by the CLI.
    [[nodiscard]] std::string toLine(bool color) const;
};

/// Heuristic scoring engine: turns structural observations into a weighted,
/// explainable score. Every contribution carries its own justification so a
/// verdict can always be defended to the user — an unexplainable detection is
/// an unactionable one.
struct HeuristicConfig {
    double suspiciousThreshold = 40.0;
    double maliciousThreshold  = 75.0;
    bool   trustSignedBinaries = true;
    double signedDiscount      = 25.0;   ///< score reduction for a valid signature
};

class HeuristicEngine {
public:
    using Config = HeuristicConfig;

    HeuristicEngine() = default;
    explicit HeuristicEngine(Config cfg) : cfg_(cfg) {}

    /// Appends heuristic detections to `verdict` and sets `score`/`disposition`.
    void evaluate(FileVerdict& verdict, ByteView data) const;

    [[nodiscard]] const Config& config() const { return cfg_; }

private:
    Config cfg_{};
};

}  // namespace shiranui
