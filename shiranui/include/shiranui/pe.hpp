// SPDX-License-Identifier: MIT
// Portable, bounds-checked PE/COFF parser.
//
// This parser never dereferences the image as a loaded module and never relies
// on <winnt.h>; it treats the input strictly as untrusted bytes. Every field
// access is range-checked, malformed structures degrade into recorded
// anomalies rather than errors, and no allocation is driven by an unvalidated
// length field. That makes it safe to run against hostile samples and lets the
// whole parser be fuzz-tested on any host OS.
#pragma once

#include <map>
#include <string>
#include <vector>

#include "shiranui/common.hpp"

namespace shiranui::pe {

enum class Machine : u16 {
    Unknown = 0x0000,
    I386    = 0x014c,
    Amd64   = 0x8664,
    Arm     = 0x01c0,
    ArmNT   = 0x01c4,
    Arm64   = 0xaa64,
    IA64    = 0x0200,
    RiscV64 = 0x5064,
};

enum class Subsystem : u16 {
    Unknown          = 0,
    Native           = 1,
    WindowsGui       = 2,
    WindowsCui       = 3,
    EfiApplication   = 10,
    EfiBootDriver    = 11,
    EfiRuntimeDriver = 12,
};

// IMAGE_FILE_* characteristics
constexpr u16 kFileExecutableImage = 0x0002;
constexpr u16 kFileDll             = 0x2000;
constexpr u16 kFileSystem          = 0x1000;

// IMAGE_DLLCHARACTERISTICS_*
constexpr u16 kDllHighEntropyVa  = 0x0020;
constexpr u16 kDllDynamicBase    = 0x0040;
constexpr u16 kDllForceIntegrity = 0x0080;
constexpr u16 kDllNxCompat       = 0x0100;
constexpr u16 kDllNoSeh          = 0x0400;
constexpr u16 kDllGuardCf        = 0x4000;

// IMAGE_SCN_* section characteristics
constexpr u32 kScnCntCode         = 0x00000020;
constexpr u32 kScnCntInitData     = 0x00000040;
constexpr u32 kScnCntUninitData   = 0x00000080;
constexpr u32 kScnMemDiscardable  = 0x02000000;
constexpr u32 kScnMemShared       = 0x10000000;
constexpr u32 kScnMemExecute      = 0x20000000;
constexpr u32 kScnMemRead         = 0x40000000;
constexpr u32 kScnMemWrite        = 0x80000000;

struct Section {
    std::string name;
    u32         virtualAddress = 0;
    u32         virtualSize    = 0;
    u32         rawOffset      = 0;
    u32         rawSize        = 0;
    u32         characteristics = 0;
    double      entropy        = 0.0;

    [[nodiscard]] bool executable() const { return (characteristics & kScnMemExecute) != 0; }
    [[nodiscard]] bool writable() const { return (characteristics & kScnMemWrite) != 0; }
    [[nodiscard]] bool code() const { return (characteristics & kScnCntCode) != 0; }
};

struct ImportedDll {
    std::string              name;
    std::vector<std::string> functions;   ///< "ordinal#N" for ordinal-only imports
    bool                     delayLoad = false;
};

struct RichEntry {
    u16 productId = 0;
    u16 buildId   = 0;
    u32 count     = 0;
};

struct Info {
    bool        valid       = false;      ///< a PE header was located and parsed
    std::string parseError;               ///< set when valid == false

    Machine   machine   = Machine::Unknown;
    Subsystem subsystem = Subsystem::Unknown;
    bool      is64Bit   = false;
    bool      isDll     = false;
    bool      isDriver  = false;
    bool      isDotNet  = false;

    u16 fileCharacteristics = 0;
    u16 dllCharacteristics  = 0;
    u32 timestamp           = 0;

    u64 imageBase       = 0;
    u32 entryPointRva   = 0;
    i32 entryPointSection = -1;           ///< index into `sections`, -1 if outside
    u32 sizeOfImage     = 0;
    u32 sizeOfHeaders   = 0;
    u32 sectionAlignment = 0;
    u32 fileAlignment    = 0;

    u32  headerChecksum     = 0;
    u32  computedChecksum   = 0;
    bool checksumValid      = false;

    std::vector<Section>     sections;
    std::vector<ImportedDll> imports;
    std::vector<std::string> exports;
    std::string              exportModuleName;

    std::string imphash;                  ///< pefile-compatible import hash (MD5)
    std::string richHash;                 ///< SHA-256 of the decoded Rich header
    std::vector<RichEntry> richEntries;

    bool hasTls              = false;
    u32  tlsCallbackCount    = 0;
    bool hasRelocations      = false;
    bool hasResources        = false;
    u32  resourceCount       = 0;
    bool hasDebugDirectory   = false;
    std::string pdbPath;

    bool hasAuthenticodeDirectory = false; ///< embedded WIN_CERTIFICATE blob present
    u32  authenticodeSize         = 0;

    u64 overlayOffset = 0;
    u64 overlaySize   = 0;
    double overlayEntropy = 0.0;

    /// Structural oddities: not verdicts, just observations for the scorer.
    std::vector<std::string> anomalies;

    [[nodiscard]] const Section* sectionForRva(u32 rva) const;
    [[nodiscard]] std::string    machineName() const;
    [[nodiscard]] std::string    subsystemName() const;
};

/// Returns true when `data` starts with an MZ header (cheap pre-filter).
bool looksLikePe(ByteView data);

/// Parses `data`. Never throws; on malformed input returns Info{valid=false}
/// with `parseError` populated.
Info parse(ByteView data);

/// Recomputes the PE header checksum exactly as Microsoft's CheckSumMappedFile does.
u32 computeChecksum(ByteView data, u32 checksumFieldOffset);

}  // namespace shiranui::pe
