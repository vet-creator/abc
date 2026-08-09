// SPDX-License-Identifier: MIT
#include "shiranui/verdict.hpp"

#include <algorithm>
#include <sstream>

#include "shiranui/analysis.hpp"

namespace shiranui {

std::string_view severityName(Severity s) {
    switch (s) {
        case Severity::Info:     return "info";
        case Severity::Low:      return "low";
        case Severity::Medium:   return "medium";
        case Severity::High:     return "high";
        case Severity::Critical: return "critical";
    }
    return "info";
}

std::optional<Severity> severityFromName(std::string_view s) {
    std::string l = toLowerAscii(s);
    if (l == "info")     return Severity::Info;
    if (l == "low")      return Severity::Low;
    if (l == "medium")   return Severity::Medium;
    if (l == "high")     return Severity::High;
    if (l == "critical") return Severity::Critical;
    return std::nullopt;
}

std::string_view dispositionName(Disposition d) {
    switch (d) {
        case Disposition::Clean:      return "clean";
        case Disposition::Suspicious: return "suspicious";
        case Disposition::Malicious:  return "malicious";
        case Disposition::Error:      return "error";
    }
    return "clean";
}

Severity FileVerdict::maxSeverity() const {
    Severity m = Severity::Info;
    for (const Detection& d : detections)
        if (static_cast<int>(d.severity) > static_cast<int>(m)) m = d.severity;
    return m;
}

std::string FileVerdict::toJson() const {
    std::ostringstream o;
    o << "{\"path\":\"" << jsonEscape(pathToUtf8(path)) << "\""
      << ",\"size\":" << size
      << ",\"disposition\":\"" << dispositionName(disposition) << "\""
      << ",\"score\":" << fmtDouble(score, 1)
      << ",\"sha256\":\"" << sha256 << "\"";
    if (!fuzzyHash.empty()) o << ",\"fuzzy\":\"" << jsonEscape(fuzzyHash) << "\"";
    if (!error.empty())     o << ",\"error\":\"" << jsonEscape(error) << "\"";
    o << ",\"pe\":" << (isPe ? "true" : "false");
    if (isPe && peInfo.valid) {
        o << ",\"pe_info\":{\"machine\":\"" << jsonEscape(peInfo.machineName()) << "\""
          << ",\"subsystem\":\"" << jsonEscape(peInfo.subsystemName()) << "\""
          << ",\"dll\":" << (peInfo.isDll ? "true" : "false")
          << ",\"dotnet\":" << (peInfo.isDotNet ? "true" : "false")
          << ",\"timestamp\":" << peInfo.timestamp
          << ",\"imphash\":\"" << peInfo.imphash << "\""
          << ",\"sections\":" << peInfo.sections.size()
          << ",\"overlay_size\":" << peInfo.overlaySize << "}";
    }
    if (signatureChecked) {
        o << ",\"signature\":{\"valid\":" << (signatureValid ? "true" : "false")
          << ",\"signer\":\"" << jsonEscape(signerName) << "\""
          << ",\"status\":\"" << jsonEscape(signatureStatus) << "\"}";
    }
    o << ",\"detections\":[";
    for (std::size_t i = 0; i < detections.size(); ++i) {
        const Detection& d = detections[i];
        if (i) o << ",";
        o << "{\"source\":\"" << jsonEscape(d.source) << "\""
          << ",\"name\":\"" << jsonEscape(d.name) << "\""
          << ",\"severity\":\"" << severityName(d.severity) << "\""
          << ",\"weight\":" << fmtDouble(d.weight, 1)
          << ",\"offset\":" << d.offset
          << ",\"description\":\"" << jsonEscape(d.description) << "\"";
        if (!d.matchedStrings.empty()) {
            o << ",\"strings\":[";
            for (std::size_t k = 0; k < d.matchedStrings.size(); ++k) {
                if (k) o << ",";
                o << "\"" << jsonEscape(d.matchedStrings[k]) << "\"";
            }
            o << "]";
        }
        o << "}";
    }
    o << "]}";
    return o.str();
}

std::string FileVerdict::toLine(bool color) const {
    const char* c = "";
    const char* r = color ? "\x1b[0m" : "";
    if (color) {
        switch (disposition) {
            case Disposition::Malicious:  c = "\x1b[1;31m"; break;
            case Disposition::Suspicious: c = "\x1b[1;33m"; break;
            case Disposition::Error:      c = "\x1b[35m";   break;
            default:                      c = "\x1b[32m";   break;
        }
    }
    std::string label;
    switch (disposition) {
        case Disposition::Malicious:  label = "MALICIOUS "; break;
        case Disposition::Suspicious: label = "SUSPICIOUS"; break;
        case Disposition::Error:      label = "ERROR     "; break;
        default:                      label = "clean     "; break;
    }
    std::string out = std::string(c) + label + r + "  " + pathToUtf8(path);
    if (disposition != Disposition::Clean) {
        out += "  [score " + fmtDouble(score, 1) + "]";
        if (!detections.empty()) {
            std::vector<std::string> names;
            for (std::size_t i = 0; i < detections.size() && i < 3; ++i)
                names.push_back(detections[i].name);
            out += " " + join(names, ", ");
            if (detections.size() > 3) out += " (+" + fmtU64(detections.size() - 3) + ")";
        }
    }
    if (!error.empty()) out += "  (" + error + ")";
    return out;
}

// ---------------------------------------------------------------------------
// Heuristics
// ---------------------------------------------------------------------------
namespace {

struct ApiGroup {
    const char* name;
    const char* description;
    Severity    severity;
    double      weight;
    std::vector<const char*> apis;
    std::size_t minHits;
};

const std::vector<ApiGroup>& apiGroups() {
    static const std::vector<ApiGroup> kGroups = {
        {"H.Inject.RemoteThread", "Classic remote-process code injection API set",
         Severity::High, 26.0,
         {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}, 3},
        {"H.Inject.SectionMap", "Section-mapping injection (NtMapViewOfSection family)",
         Severity::High, 24.0,
         {"NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection", "ZwMapViewOfSection"}, 2},
        {"H.Inject.APC", "Asynchronous-procedure-call injection",
         Severity::High, 22.0, {"QueueUserAPC", "NtQueueApcThread", "OpenThread"}, 2},
        {"H.Hollowing", "Process hollowing indicators",
         Severity::High, 24.0,
         {"CreateProcessInternalW", "SetThreadContext", "GetThreadContext", "ResumeThread",
          "NtUnmapViewOfSection"}, 3},
        {"H.Dynamic.Resolve", "Runtime API resolution, typical of packed or staged code",
         Severity::Low, 8.0, {"LoadLibraryA", "GetProcAddress", "GetModuleHandleA"}, 3},
        {"H.Persistence.Registry", "Writes autostart registry values",
         Severity::Medium, 14.0, {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
                                   "RegCreateKeyExW"}, 2},
        {"H.Persistence.Service", "Creates or modifies Windows services",
         Severity::Medium, 14.0, {"OpenSCManagerA", "OpenSCManagerW", "CreateServiceA",
                                   "CreateServiceW", "ChangeServiceConfigA"}, 2},
        {"H.AntiDebug", "Anti-analysis and debugger-evasion checks",
         Severity::Medium, 12.0,
         {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
          "OutputDebugStringA", "NtSetInformationThread"}, 2},
        {"H.Crypto.Ransom", "Bulk cryptography plus file enumeration (ransomware pattern)",
         Severity::High, 20.0,
         {"CryptEncrypt", "CryptGenKey", "CryptAcquireContextA", "CryptAcquireContextW",
          "BCryptEncrypt", "FindFirstFileW", "FindNextFileW"}, 3},
        {"H.Network.Download", "Downloads remote content",
         Severity::Medium, 12.0,
         {"URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA", "InternetReadFile",
          "WinHttpOpenRequest", "HttpSendRequestA"}, 2},
        {"H.Credential.Access", "Touches credential and LSA interfaces",
         Severity::High, 22.0,
         {"LsaOpenPolicy", "LsaRetrievePrivateData", "CredEnumerateA", "CredEnumerateW",
          "SamIConnect", "MiniDumpWriteDump"}, 2},
        {"H.Keylogger", "Keyboard and input capture",
         Severity::High, 20.0,
         {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetForegroundWindow",
          "RegisterRawInputDevices"}, 2},
        {"H.Privilege", "Token and privilege manipulation",
         Severity::Medium, 12.0,
         {"AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
          "DuplicateTokenEx", "ImpersonateLoggedOnUser"}, 2},
        {"H.Shadow.Delete", "Deletes backups or shadow copies (destructive intent)",
         Severity::Critical, 34.0,
         {"DeleteFileW", "SHEmptyRecycleBinW", "FindFirstVolumeW", "DeviceIoControl"}, 3},
    };
    return kGroups;
}

void addDetection(FileVerdict& v, double& score, const char* source, std::string name,
                  std::string description, Severity sev, double weight, u64 offset = 0) {
    Detection d;
    d.source      = source;
    d.name        = std::move(name);
    d.description = std::move(description);
    d.severity    = sev;
    d.weight      = weight;
    d.offset      = offset;
    v.detections.push_back(std::move(d));
    score += weight;
}

}  // namespace

void HeuristicEngine::evaluate(FileVerdict& v, ByteView data) const {
    double score = 0.0;
    for (const Detection& d : v.detections) score += d.weight;   // signature hits already scored

    if (v.isPe && v.peInfo.valid) {
        const pe::Info& pi = v.peInfo;

        // ---- Structural anomalies ------------------------------------
        for (const std::string& a : pi.anomalies) {
            double   w   = 3.0;
            Severity sev = Severity::Info;
            if (a.find("writable and executable") != std::string::npos) { w = 18.0; sev = Severity::High; }
            else if (a.find("outside every section") != std::string::npos) { w = 20.0; sev = Severity::High; }
            else if (a.find("non-executable section") != std::string::npos) { w = 16.0; sev = Severity::High; }
            else if (a.find("very high entropy") != std::string::npos) { w = 10.0; sev = Severity::Medium; }
            else if (a.find("extends past end of file") != std::string::npos) { w = 14.0; sev = Severity::High; }
            else if (a.find("no import table") != std::string::npos) { w = 12.0; sev = Severity::Medium; }
            else if (a.find("only") != std::string::npos && a.find("function") != std::string::npos) { w = 9.0; sev = Severity::Medium; }
            else if (a.find("non-printable") != std::string::npos) { w = 12.0; sev = Severity::Medium; }
            else if (a.find("TLS callback") != std::string::npos) { w = 6.0; sev = Severity::Low; }
            else if (a.find("checksum") != std::string::npos) { w = 2.0; sev = Severity::Info; }
            else if (a.find("ASLR disabled") != std::string::npos ||
                     a.find("DEP disabled") != std::string::npos) { w = 4.0; sev = Severity::Low; }
            else if (a.find("Control Flow Guard") != std::string::npos) { w = 0.5; sev = Severity::Info; }
            else if (a.find("overlay occupies") != std::string::npos) { w = 8.0; sev = Severity::Medium; }
            addDetection(v, score, "heuristic", "H.PE.Structure", a, sev, w);
        }

        // ---- Packing --------------------------------------------------
        double codeEntropy = 0.0;
        for (const pe::Section& s : pi.sections)
            if (s.code() || s.executable()) codeEntropy = std::max(codeEntropy, s.entropy);
        if (codeEntropy > 7.2 && codeEntropy <= 7.5)
            addDetection(v, score, "heuristic", "H.Packed.Likely",
                         "Executable section entropy " + fmtDouble(codeEntropy) +
                             " suggests compression or packing",
                         Severity::Low, 6.0);

        std::size_t totalImports = 0;
        for (const pe::ImportedDll& d : pi.imports) totalImports += d.functions.size();
        if (codeEntropy > 7.4 && totalImports < 15 && !pi.isDotNet)
            addDetection(v, score, "heuristic", "H.Packed.Strong",
                         "High-entropy code with a near-empty import table is the classic "
                         "runtime-unpacker signature",
                         Severity::High, 20.0);

        // ---- Suspicious API groupings ---------------------------------
        std::vector<std::string> flatImports;
        flatImports.reserve(totalImports);
        for (const pe::ImportedDll& d : pi.imports)
            for (const std::string& f : d.functions) flatImports.push_back(toLowerAscii(f));

        for (const ApiGroup& g : apiGroups()) {
            std::vector<std::string> hits;
            for (const char* api : g.apis) {
                std::string needle = toLowerAscii(api);
                if (std::find(flatImports.begin(), flatImports.end(), needle) != flatImports.end())
                    hits.push_back(api);
            }
            if (hits.size() >= g.minHits) {
                Detection d;
                d.source         = "heuristic";
                d.name           = g.name;
                d.description    = std::string(g.description) + ": " + join(hits, ", ");
                d.severity       = g.severity;
                d.weight         = g.weight;
                d.matchedStrings = hits;
                v.detections.push_back(std::move(d));
                score += g.weight;
            }
        }

        // ---- Masquerading ---------------------------------------------
        if (pi.isDriver && !(pi.dllCharacteristics & pe::kDllForceIntegrity))
            addDetection(v, score, "heuristic", "H.Driver.Unsigned",
                         "Kernel driver image without FORCE_INTEGRITY", Severity::High, 16.0);

        if (pi.overlaySize > 0 && pi.overlayEntropy > 7.5 && pi.overlaySize > 0x2000)
            addDetection(v, score, "heuristic", "H.Overlay.Encrypted",
                         "High-entropy overlay of " + humanSize(pi.overlaySize) +
                             " appended after the last section (embedded payload pattern)",
                         Severity::Medium, 14.0);

        if (!pi.pdbPath.empty()) {
            std::string lower = toLowerAscii(pi.pdbPath);
            for (const char* marker : {"\\hack", "\\crypter", "\\stealer", "\\rat\\", "\\keylog",
                                       "\\ransom", "\\loader\\", "\\injector"}) {
                if (lower.find(marker) != std::string::npos) {
                    addDetection(v, score, "heuristic", "H.PDB.Suspicious",
                                 "Debug path reveals project name: " + pi.pdbPath,
                                 Severity::High, 22.0);
                    break;
                }
            }
        }
    } else if (!data.empty()) {
        // ---- Non-PE content -------------------------------------------
        double h = analysis::shannonEntropy(data);
        if (data.size() > 4096 && h > 7.9 && analysis::printableRatio(data) < 0.1)
            addDetection(v, score, "heuristic", "H.Data.Encrypted",
                         "Uniformly random content (entropy " + fmtDouble(h) +
                             ") with no printable structure",
                         Severity::Low, 5.0);
    }

    // ---- Signature trust adjustment -----------------------------------
    if (cfg_.trustSignedBinaries && v.signatureChecked && v.signatureValid) {
        double before = score;
        score         = std::max(0.0, score - cfg_.signedDiscount);
        if (before != score) {
            Detection d;
            d.source      = "authenticode";
            d.name        = "T.Signed.Valid";
            d.description = "Valid Authenticode signature" +
                            (v.signerName.empty() ? std::string() : " by " + v.signerName) +
                            " reduces the heuristic score";
            d.severity = Severity::Info;
            d.weight   = -(before - score);
            v.detections.push_back(std::move(d));
        }
    }

    v.score = std::min(100.0, std::max(0.0, score));

    // Any signature or hash hit is decisive on its own.
    bool decisive = false;
    for (const Detection& d : v.detections) {
        if ((d.source == "signature" || d.source == "hash") &&
            static_cast<int>(d.severity) >= static_cast<int>(Severity::High)) {
            decisive = true;
            break;
        }
    }

    if (v.disposition == Disposition::Error) return;
    if (decisive || v.score >= cfg_.maliciousThreshold)      v.disposition = Disposition::Malicious;
    else if (v.score >= cfg_.suspiciousThreshold)            v.disposition = Disposition::Suspicious;
    else                                                     v.disposition = Disposition::Clean;
}

}  // namespace shiranui
