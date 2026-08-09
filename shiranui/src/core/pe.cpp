// SPDX-License-Identifier: MIT
#include "shiranui/pe.hpp"

#include <algorithm>
#include <cstring>

#include "shiranui/analysis.hpp"
#include "shiranui/crypto.hpp"

namespace shiranui::pe {

namespace {

/// Bounds-checked little-endian cursor over untrusted bytes.
class Reader {
public:
    explicit Reader(ByteView d) : d_(d) {}

    [[nodiscard]] bool has(std::size_t off, std::size_t n) const {
        return off <= d_.size() && n <= d_.size() - off;
    }
    [[nodiscard]] u8  u8At(std::size_t o) const { return has(o, 1) ? d_[o] : 0; }
    [[nodiscard]] u16 u16At(std::size_t o) const {
        if (!has(o, 2)) return 0;
        return static_cast<u16>(d_[o] | (d_[o + 1] << 8));
    }
    [[nodiscard]] u32 u32At(std::size_t o) const {
        if (!has(o, 4)) return 0;
        return static_cast<u32>(d_[o]) | (static_cast<u32>(d_[o + 1]) << 8) |
               (static_cast<u32>(d_[o + 2]) << 16) | (static_cast<u32>(d_[o + 3]) << 24);
    }
    [[nodiscard]] u64 u64At(std::size_t o) const {
        if (!has(o, 8)) return 0;
        return static_cast<u64>(u32At(o)) | (static_cast<u64>(u32At(o + 4)) << 32);
    }
    /// Reads a NUL-terminated ASCII string, capped at `maxLen` bytes.
    [[nodiscard]] std::string cstrAt(std::size_t o, std::size_t maxLen = 512) const {
        std::string s;
        for (std::size_t i = 0; i < maxLen && has(o + i, 1); ++i) {
            u8 c = d_[o + i];
            if (c == 0) break;
            s.push_back(static_cast<char>(c));
        }
        return s;
    }
    [[nodiscard]] std::size_t size() const { return d_.size(); }
    [[nodiscard]] ByteView    slice(std::size_t o, std::size_t n) const {
        if (!has(o, n)) return {};
        return d_.subspan(o, n);
    }

private:
    ByteView d_;
};

constexpr std::size_t kSectionHeaderSize = 40;
constexpr std::size_t kMaxSections       = 96;     // PE spec practical ceiling
constexpr std::size_t kMaxImportDlls     = 512;
constexpr std::size_t kMaxImportsPerDll  = 8192;
constexpr std::size_t kMaxExports        = 16384;
constexpr std::size_t kMaxResourceNodes  = 8192;

const char* kKnownSectionNames[] = {".text",  ".data",  ".rdata", ".bss",   ".idata", ".edata",
                                    ".pdata", ".rsrc",  ".reloc", ".tls",   ".debug", ".didat",
                                    ".sdata", ".xdata", ".00cfg", ".gfids", ".textbss", "INIT",
                                    "PAGE",   ".CRT",   ".sxdata", ".detourc", ".detourd"};

bool isKnownSectionName(const std::string& n) {
    for (const char* k : kKnownSectionNames)
        if (n == k) return true;
    return false;
}

std::string stripDllExtension(std::string name) {
    std::string lower = toLowerAscii(name);
    for (const char* ext : {".dll", ".ocx", ".sys"}) {
        if (endsWith(lower, ext)) return lower.substr(0, lower.size() - 4);
    }
    return lower;
}

}  // namespace

const Section* Info::sectionForRva(u32 rva) const {
    for (const Section& s : sections) {
        u32 size = s.virtualSize ? s.virtualSize : s.rawSize;
        if (rva >= s.virtualAddress && rva < s.virtualAddress + size) return &s;
    }
    return nullptr;
}

std::string Info::machineName() const {
    switch (machine) {
        case Machine::I386:    return "x86";
        case Machine::Amd64:   return "x64";
        case Machine::Arm:     return "ARM";
        case Machine::ArmNT:   return "ARM (Thumb-2)";
        case Machine::Arm64:   return "ARM64";
        case Machine::IA64:    return "IA-64";
        case Machine::RiscV64: return "RISC-V 64";
        default:               return "unknown(0x" + fmtHex(static_cast<u64>(machine), 4) + ")";
    }
}

std::string Info::subsystemName() const {
    switch (subsystem) {
        case Subsystem::Native:           return "native";
        case Subsystem::WindowsGui:       return "windows-gui";
        case Subsystem::WindowsCui:       return "windows-console";
        case Subsystem::EfiApplication:   return "efi-application";
        case Subsystem::EfiBootDriver:    return "efi-boot-driver";
        case Subsystem::EfiRuntimeDriver: return "efi-runtime-driver";
        default:                          return "unknown";
    }
}

bool looksLikePe(ByteView data) {
    return data.size() >= 0x40 && data[0] == 'M' && data[1] == 'Z';
}

u32 computeChecksum(ByteView data, u32 checksumFieldOffset) {
    // 16-bit one's-complement sum of the whole file with the CheckSum field
    // treated as zero, folded to 32 bits, plus the file length.
    u64         sum = 0;
    std::size_t i   = 0;
    const std::size_t n = data.size();
    for (; i + 1 < n; i += 2) {
        u32 word = static_cast<u32>(data[i]) | (static_cast<u32>(data[i + 1]) << 8);
        if (i >= checksumFieldOffset && i < checksumFieldOffset + 4) word = 0;
        sum += word;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if (i < n) {
        sum += data[i];
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<u32>(sum) + static_cast<u32>(n);
}

namespace {

void parseRichHeader(const Reader& r, std::size_t lfanew, Info& info) {
    // The Rich header sits between the DOS stub and the PE signature. Layout is
    // "DanS" ^ key, three zero DWORDs, then (compid, count) pairs, then "Rich",
    // then the key. Everything before "Rich" is XOR-encoded with that key.
    if (lfanew < 0x80 || lfanew > r.size()) return;
    std::size_t richOff = 0;
    for (std::size_t off = lfanew >= 4 ? lfanew - 4 : 0; off >= 0x40; off -= 4) {
        if (r.u32At(off) == 0x68636952u) { richOff = off; break; }  // "Rich"
        if (off < 4) break;
    }
    if (!richOff) return;

    const u32 key = r.u32At(richOff + 4);
    // Walk backwards to "DanS"
    std::size_t dansOff = 0;
    for (std::size_t off = richOff; off >= 0x40; off -= 4) {
        if ((r.u32At(off) ^ key) == 0x536e6144u) { dansOff = off; break; }  // "DanS"
        if (off < 4) break;
    }
    if (!dansOff || dansOff + 16 > richOff) return;

    Bytes decoded;
    for (std::size_t off = dansOff; off < richOff; off += 4) {
        u32 v = r.u32At(off) ^ key;
        decoded.push_back(static_cast<u8>(v));
        decoded.push_back(static_cast<u8>(v >> 8));
        decoded.push_back(static_cast<u8>(v >> 16));
        decoded.push_back(static_cast<u8>(v >> 24));
    }
    info.richHash = crypto::Sha256::hex(ByteView(decoded.data(), decoded.size()));

    for (std::size_t off = dansOff + 16; off + 8 <= richOff; off += 8) {
        u32 comp  = r.u32At(off) ^ key;
        u32 count = r.u32At(off + 4) ^ key;
        if (comp == 0 && count == 0) continue;
        info.richEntries.push_back(RichEntry{static_cast<u16>(comp >> 16),
                                             static_cast<u16>(comp & 0xffff), count});
        if (info.richEntries.size() > 256) break;
    }
}

u32 rvaToOffset(const Info& info, u32 rva) {
    for (const Section& s : info.sections) {
        u32 vsize = s.virtualSize ? s.virtualSize : s.rawSize;
        if (rva >= s.virtualAddress && rva < s.virtualAddress + vsize) {
            u32 delta = rva - s.virtualAddress;
            if (delta >= s.rawSize) return 0;   // lives in uninitialised space
            return s.rawOffset + delta;
        }
    }
    // Header-resident RVAs map 1:1.
    if (rva < info.sizeOfHeaders) return rva;
    return 0;
}

void parseImports(const Reader& r, Info& info, u32 dirRva, u32 dirSize, bool delayLoad) {
    if (!dirRva || !dirSize) return;
    u32 base = rvaToOffset(info, dirRva);
    if (!base) { info.anomalies.push_back("import directory RVA does not map to file data"); return; }

    const std::size_t descSize = delayLoad ? 32 : 20;
    for (std::size_t i = 0; i < kMaxImportDlls; ++i) {
        std::size_t desc = base + i * descSize;
        if (!r.has(desc, descSize)) break;

        u32 nameRva, thunkRva;
        if (delayLoad) {
            nameRva  = r.u32At(desc + 4);
            thunkRva = r.u32At(desc + 16);   // ImportNameTableRVA
        } else {
            u32 originalFirstThunk = r.u32At(desc + 0);
            nameRva                = r.u32At(desc + 12);
            u32 firstThunk         = r.u32At(desc + 16);
            thunkRva               = originalFirstThunk ? originalFirstThunk : firstThunk;
        }
        if (!nameRva && !thunkRva) break;   // terminating null descriptor

        ImportedDll dll;
        dll.delayLoad = delayLoad;
        u32 nameOff   = rvaToOffset(info, nameRva);
        dll.name      = nameOff ? r.cstrAt(nameOff, 256) : std::string();
        if (dll.name.empty()) { if (!thunkRva) break; dll.name = "<unnamed>"; }

        u32 thunkOff = rvaToOffset(info, thunkRva);
        if (thunkOff) {
            const std::size_t step  = info.is64Bit ? 8 : 4;
            const u64         ordFlag = info.is64Bit ? 0x8000000000000000ull : 0x80000000ull;
            for (std::size_t k = 0; k < kMaxImportsPerDll; ++k) {
                std::size_t at = thunkOff + k * step;
                if (!r.has(at, step)) break;
                u64 entry = info.is64Bit ? r.u64At(at) : r.u32At(at);
                if (!entry) break;
                if (entry & ordFlag) {
                    dll.functions.push_back("ordinal#" + fmtU64(entry & 0xffff));
                } else {
                    u32 hintOff = rvaToOffset(info, static_cast<u32>(entry & 0x7fffffffu));
                    if (!hintOff) continue;
                    std::string fn = r.cstrAt(hintOff + 2, 256);
                    if (!fn.empty()) dll.functions.push_back(std::move(fn));
                }
            }
        }
        info.imports.push_back(std::move(dll));
    }
}

void computeImphash(Info& info) {
    // pefile semantics: lowercase, module extension stripped for dll/ocx/sys,
    // "module.function" joined with commas; ordinals rendered as "ord<N>".
    std::vector<std::string> parts;
    for (const ImportedDll& d : info.imports) {
        if (d.delayLoad) continue;
        std::string mod = stripDllExtension(d.name);
        for (const std::string& fn : d.functions) {
            std::string f = toLowerAscii(fn);
            if (startsWith(f, "ordinal#")) f = "ord" + f.substr(8);
            parts.push_back(mod + "." + f);
        }
    }
    if (parts.empty()) return;
    std::string joined = join(parts, ",");
    info.imphash = crypto::Md5::hex(
        ByteView(reinterpret_cast<const u8*>(joined.data()), joined.size()));
}

void parseExports(const Reader& r, Info& info, u32 dirRva, u32 dirSize) {
    if (!dirRva || !dirSize) return;
    u32 base = rvaToOffset(info, dirRva);
    if (!base || !r.has(base, 40)) return;

    u32 nameRva      = r.u32At(base + 12);
    u32 numNames     = r.u32At(base + 24);
    u32 namesRva     = r.u32At(base + 32);
    u32 nameOff      = rvaToOffset(info, nameRva);
    if (nameOff) info.exportModuleName = r.cstrAt(nameOff, 256);

    u32 namesOff = rvaToOffset(info, namesRva);
    if (!namesOff) return;
    u32 limit = std::min<u32>(numNames, static_cast<u32>(kMaxExports));
    for (u32 i = 0; i < limit; ++i) {
        if (!r.has(namesOff + 4ull * i, 4)) break;
        u32 off = rvaToOffset(info, r.u32At(namesOff + 4ull * i));
        if (!off) continue;
        std::string n = r.cstrAt(off, 256);
        if (!n.empty()) info.exports.push_back(std::move(n));
    }
}

void countResources(const Reader& r, Info& info, u32 dirRva) {
    u32 base = rvaToOffset(info, dirRva);
    if (!base) return;
    // Iterative depth-first walk of the resource tree with a hard node budget.
    struct Frame { u32 offset; int depth; };
    std::vector<Frame> stack{{base, 0}};
    u32                nodes = 0;
    while (!stack.empty() && nodes < kMaxResourceNodes) {
        Frame f = stack.back();
        stack.pop_back();
        if (f.depth > 3 || !r.has(f.offset, 16)) continue;
        u32 named = r.u16At(f.offset + 12);
        u32 idd   = r.u16At(f.offset + 14);
        u32 total = named + idd;
        if (total > 4096) total = 4096;
        for (u32 i = 0; i < total; ++i) {
            std::size_t entry = f.offset + 16 + 8ull * i;
            if (!r.has(entry, 8)) break;
            u32 offField = r.u32At(entry + 4);
            if (offField & 0x80000000u) {
                stack.push_back(Frame{base + (offField & 0x7fffffffu), f.depth + 1});
            } else {
                ++info.resourceCount;
            }
            if (++nodes >= kMaxResourceNodes) break;
        }
    }
}

void parseTls(const Reader& r, Info& info, u32 dirRva) {
    u32 off = rvaToOffset(info, dirRva);
    if (!off) return;
    info.hasTls = true;
    u64 callbackVa = info.is64Bit ? r.u64At(off + 24) : r.u32At(off + 12);
    if (!callbackVa || callbackVa < info.imageBase) return;
    u32 cbOff = rvaToOffset(info, static_cast<u32>(callbackVa - info.imageBase));
    if (!cbOff) return;
    const std::size_t step = info.is64Bit ? 8 : 4;
    for (u32 i = 0; i < 64; ++i) {
        std::size_t at = cbOff + i * step;
        if (!r.has(at, step)) break;
        u64 v = info.is64Bit ? r.u64At(at) : r.u32At(at);
        if (!v) break;
        ++info.tlsCallbackCount;
    }
}

void parseDebug(const Reader& r, Info& info, u32 dirRva, u32 dirSize) {
    u32 off = rvaToOffset(info, dirRva);
    if (!off || dirSize < 28) return;
    info.hasDebugDirectory = true;
    u32 entries = std::min<u32>(dirSize / 28, 32);
    for (u32 i = 0; i < entries; ++i) {
        std::size_t e = off + 28ull * i;
        if (!r.has(e, 28)) break;
        u32 type    = r.u32At(e + 12);
        u32 dataOff = r.u32At(e + 24);
        if (type != 2 /* CODEVIEW */ || !dataOff) continue;
        u32 sig = r.u32At(dataOff);
        if (sig == 0x53445352u /* RSDS */) {
            info.pdbPath = r.cstrAt(dataOff + 24, 260);
        } else if (sig == 0x3031424eu /* NB10 */) {
            info.pdbPath = r.cstrAt(dataOff + 16, 260);
        }
        if (!info.pdbPath.empty()) break;
    }
}

void detectAnomalies(Info& info, std::size_t fileSize) {
    // Entry point
    if (info.entryPointRva == 0 && !info.isDll)
        info.anomalies.push_back("entry point RVA is zero");
    if (info.entryPointSection < 0 && info.entryPointRva != 0)
        info.anomalies.push_back("entry point lies outside every section");
    else if (info.entryPointSection >= 0) {
        const Section& s = info.sections[static_cast<std::size_t>(info.entryPointSection)];
        if (!s.executable())
            info.anomalies.push_back("entry point is in a non-executable section (" + s.name + ")");
        if (s.writable())
            info.anomalies.push_back("entry point section is writable (" + s.name + ")");
    }

    // Sections
    if (info.sections.empty()) info.anomalies.push_back("no sections");
    u32 prevEnd = 0;
    for (const Section& s : info.sections) {
        if (s.writable() && s.executable())
            info.anomalies.push_back("section " + s.name + " is both writable and executable");
        if (s.rawSize == 0 && s.virtualSize > 0 && !(s.characteristics & kScnCntUninitData))
            info.anomalies.push_back("section " + s.name + " has no raw data but claims content");
        if (s.rawOffset > fileSize || (s.rawOffset + static_cast<u64>(s.rawSize)) > fileSize)
            info.anomalies.push_back("section " + s.name + " extends past end of file");
        if (s.virtualSize > 0 && s.rawSize > s.virtualSize * 4 && s.rawSize > 0x1000)
            info.anomalies.push_back("section " + s.name + " raw size greatly exceeds virtual size");
        if (!s.name.empty() && !isKnownSectionName(s.name)) {
            bool printable = true;
            for (char c : s.name)
                if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7e)
                    printable = false;
            if (!printable) info.anomalies.push_back("section name contains non-printable bytes");
        }
        if (s.virtualAddress < prevEnd)
            info.anomalies.push_back("sections are not in ascending virtual-address order");
        prevEnd = s.virtualAddress + (s.virtualSize ? s.virtualSize : s.rawSize);
        if (s.entropy > 7.5 && s.rawSize >= 0x400)
            info.anomalies.push_back("section " + s.name + " has very high entropy (" +
                                     fmtDouble(s.entropy) + ")");
    }

    // Imports
    std::size_t totalImports = 0;
    for (const ImportedDll& d : info.imports) totalImports += d.functions.size();
    if (info.imports.empty() && !info.isDotNet)
        info.anomalies.push_back("no import table");
    else if (totalImports > 0 && totalImports < 5 && !info.isDotNet)
        info.anomalies.push_back("import table has only " + fmtU64(totalImports) + " function(s)");

    // Mitigations
    if (!(info.dllCharacteristics & kDllDynamicBase)) info.anomalies.push_back("ASLR disabled (no DYNAMIC_BASE)");
    if (!(info.dllCharacteristics & kDllNxCompat))    info.anomalies.push_back("DEP disabled (no NX_COMPAT)");
    if (!(info.dllCharacteristics & kDllGuardCf))     info.anomalies.push_back("Control Flow Guard not enabled");

    // Header hygiene
    if (info.timestamp == 0) info.anomalies.push_back("zero compilation timestamp");
    if (info.headerChecksum != 0 && !info.checksumValid)
        info.anomalies.push_back("header checksum does not match file contents");
    if (info.sizeOfImage && info.sectionAlignment && (info.sizeOfImage % info.sectionAlignment))
        info.anomalies.push_back("SizeOfImage is not a multiple of SectionAlignment");
    if (info.overlaySize > 0 && info.overlaySize > fileSize / 2)
        info.anomalies.push_back("overlay occupies more than half the file (" +
                                 humanSize(info.overlaySize) + ")");
    if (info.tlsCallbackCount > 0)
        info.anomalies.push_back(fmtU64(info.tlsCallbackCount) + " TLS callback(s) registered");
}

}  // namespace

Info parse(ByteView data) {
    Info   info;
    Reader r(data);

    if (data.size() < 0x40) { info.parseError = "file smaller than a DOS header"; return info; }
    if (!(data[0] == 'M' && data[1] == 'Z')) { info.parseError = "missing MZ signature"; return info; }

    u32 lfanew = r.u32At(0x3c);
    if (lfanew < 0x40 || !r.has(lfanew, 24)) { info.parseError = "bad e_lfanew"; return info; }
    if (r.u32At(lfanew) != 0x00004550u) { info.parseError = "missing PE signature"; return info; }

    const std::size_t fileHeader = lfanew + 4;
    info.machine             = static_cast<Machine>(r.u16At(fileHeader + 0));
    const u16 numSections    = r.u16At(fileHeader + 2);
    info.timestamp           = r.u32At(fileHeader + 4);
    const u16 optHeaderSize  = r.u16At(fileHeader + 16);
    info.fileCharacteristics = r.u16At(fileHeader + 18);
    info.isDll               = (info.fileCharacteristics & kFileDll) != 0;
    info.isDriver            = (info.fileCharacteristics & kFileSystem) != 0;

    const std::size_t optHeader = fileHeader + 20;
    const u16         magic     = r.u16At(optHeader);
    if (magic == 0x20b) {
        info.is64Bit = true;
    } else if (magic == 0x10b) {
        info.is64Bit = false;
    } else {
        info.parseError = "unsupported optional header magic 0x" + fmtHex(magic, 4);
        return info;
    }

    info.entryPointRva    = r.u32At(optHeader + 16);
    info.sectionAlignment = r.u32At(optHeader + 32);
    info.fileAlignment    = r.u32At(optHeader + 36);

    std::size_t ddOffset;      // data directory array
    std::size_t checksumOff;
    if (info.is64Bit) {
        info.imageBase          = r.u64At(optHeader + 24);
        info.sizeOfImage        = r.u32At(optHeader + 56);
        info.sizeOfHeaders      = r.u32At(optHeader + 60);
        checksumOff             = optHeader + 64;
        info.subsystem          = static_cast<Subsystem>(r.u16At(optHeader + 68));
        info.dllCharacteristics = r.u16At(optHeader + 70);
        ddOffset                = optHeader + 112;
    } else {
        info.imageBase          = r.u32At(optHeader + 28);
        info.sizeOfImage        = r.u32At(optHeader + 56);
        info.sizeOfHeaders      = r.u32At(optHeader + 60);
        checksumOff             = optHeader + 64;
        info.subsystem          = static_cast<Subsystem>(r.u16At(optHeader + 68));
        info.dllCharacteristics = r.u16At(optHeader + 70);
        ddOffset                = optHeader + 96;
    }
    info.headerChecksum   = r.u32At(checksumOff);
    info.computedChecksum = computeChecksum(data, static_cast<u32>(checksumOff));
    info.checksumValid    = (info.headerChecksum == info.computedChecksum);

    const u32 numDirs = std::min<u32>(r.u32At(ddOffset - 4), 16);
    auto dirRva = [&](u32 index) -> u32 {
        return index < numDirs ? r.u32At(ddOffset + 8ull * index) : 0;
    };
    auto dirSize = [&](u32 index) -> u32 {
        return index < numDirs ? r.u32At(ddOffset + 8ull * index + 4) : 0;
    };

    // ---- Sections -----------------------------------------------------
    const std::size_t sectionTable = optHeader + optHeaderSize;
    const u16         nSec         = static_cast<u16>(std::min<std::size_t>(numSections, kMaxSections));
    if (numSections > kMaxSections)
        info.anomalies.push_back("section count " + fmtU64(numSections) + " exceeds the practical limit");

    for (u16 i = 0; i < nSec; ++i) {
        std::size_t sh = sectionTable + static_cast<std::size_t>(i) * kSectionHeaderSize;
        if (!r.has(sh, kSectionHeaderSize)) {
            info.anomalies.push_back("section table is truncated");
            break;
        }
        Section s;
        char nameBuf[9] = {0};
        for (int k = 0; k < 8; ++k) nameBuf[k] = static_cast<char>(r.u8At(sh + static_cast<std::size_t>(k)));
        s.name            = std::string(nameBuf, ::strnlen(nameBuf, 8));
        s.virtualSize     = r.u32At(sh + 8);
        s.virtualAddress  = r.u32At(sh + 12);
        s.rawSize         = r.u32At(sh + 16);
        s.rawOffset       = r.u32At(sh + 20);
        s.characteristics = r.u32At(sh + 36);

        ByteView body = r.slice(s.rawOffset, s.rawSize);
        if (!body.empty()) s.entropy = analysis::shannonEntropy(body);
        info.sections.push_back(std::move(s));
    }

    if (info.entryPointRva) {
        for (std::size_t i = 0; i < info.sections.size(); ++i) {
            const Section& s   = info.sections[i];
            u32            vsz = s.virtualSize ? s.virtualSize : s.rawSize;
            if (info.entryPointRva >= s.virtualAddress && info.entryPointRva < s.virtualAddress + vsz) {
                info.entryPointSection = static_cast<i32>(i);
                break;
            }
        }
    }

    // ---- Directories --------------------------------------------------
    info.isDotNet = dirRva(14) != 0;
    parseImports(r, info, dirRva(1), dirSize(1), false);
    parseImports(r, info, dirRva(13), dirSize(13), true);
    computeImphash(info);
    parseExports(r, info, dirRva(0), dirSize(0));

    info.hasRelocations = dirRva(5) != 0 && dirSize(5) != 0;
    if (dirRva(2)) { info.hasResources = true; countResources(r, info, dirRva(2)); }
    if (dirRva(9)) parseTls(r, info, dirRva(9));
    if (dirRva(6)) parseDebug(r, info, dirRva(6), dirSize(6));

    // The security directory is a *file offset*, not an RVA.
    if (dirRva(4) && dirSize(4)) {
        info.hasAuthenticodeDirectory = true;
        info.authenticodeSize         = dirSize(4);
    }

    parseRichHeader(r, lfanew, info);

    // ---- Overlay ------------------------------------------------------
    u64 endOfImage = info.sizeOfHeaders;
    for (const Section& s : info.sections)
        endOfImage = std::max<u64>(endOfImage, static_cast<u64>(s.rawOffset) + s.rawSize);
    if (endOfImage < data.size()) {
        info.overlayOffset = endOfImage;
        info.overlaySize   = data.size() - endOfImage;
        ByteView ov = r.slice(static_cast<std::size_t>(info.overlayOffset),
                              static_cast<std::size_t>(std::min<u64>(info.overlaySize, 1u << 20)));
        if (!ov.empty()) info.overlayEntropy = analysis::shannonEntropy(ov);
    }

    detectAnomalies(info, data.size());
    info.valid = true;
    return info;
}

}  // namespace shiranui::pe
