// SPDX-License-Identifier: MIT
// Read-only security posture audit.
//
// Every check reports what it found, where it read it from, and what to do
// about it. Nothing here modifies system configuration: an auditor that also
// changes settings is one that cannot be run safely on a production host.
#ifdef _WIN32

#include "shiranui/win/winutil.hpp"

namespace shiranui::platform {

namespace {

PostureItem make(std::string id, std::string title, bool healthy, std::string state,
                 std::string recommendation, std::string evidence) {
    PostureItem item;
    item.id             = std::move(id);
    item.title          = std::move(title);
    item.healthy        = healthy;
    item.state          = std::move(state);
    item.recommendation = std::move(recommendation);
    item.evidence       = std::move(evidence);
    return item;
}

/// Reads a DWORD policy value; `missing` is the value assumed when absent.
DWORD dwordOr(HKEY root, const wchar_t* key, const wchar_t* value, DWORD missing) {
    DWORD out = 0;
    if (reg::readDword(root, key, value, out)) return out;
    return missing;
}

bool valuePresent(HKEY root, const wchar_t* key, const wchar_t* value) {
    DWORD out = 0;
    return reg::readDword(root, key, value, out);
}

}  // namespace

std::vector<PostureItem> auditPosture() {
    std::vector<PostureItem> out;

    // ---- Microsoft Defender -------------------------------------------
    {
        const wchar_t* kDef       = L"SOFTWARE\\Microsoft\\Windows Defender";
        const wchar_t* kDefPolicy = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender";
        const wchar_t* kRtp = L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection";

        DWORD disabledAv  = dwordOr(HKEY_LOCAL_MACHINE, kDefPolicy, L"DisableAntiSpyware", 0);
        DWORD disabledRtp = dwordOr(HKEY_LOCAL_MACHINE, kRtp, L"DisableRealtimeMonitoring", 0);
        bool  healthy     = (disabledAv == 0 && disabledRtp == 0);
        out.push_back(make("defender.realtime", "Microsoft Defender real-time protection", healthy,
                           healthy ? "enabled" : "disabled",
                           healthy ? "" : "Re-enable real-time protection; a disabled AV engine is "
                                          "one of the strongest indicators of a prior compromise.",
                           "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"));

        DWORD tamper = dwordOr(HKEY_LOCAL_MACHINE,
                               L"SOFTWARE\\Microsoft\\Windows Defender\\Features",
                               L"TamperProtection", 0);
        bool tamperOn = (tamper == 5);
        out.push_back(make("defender.tamper", "Defender tamper protection", tamperOn,
                           tamperOn ? "enabled" : "disabled or unknown",
                           tamperOn ? "" : "Enable tamper protection so malware cannot switch the "
                                           "engine off through the registry.",
                           std::string(reg::keyExists(HKEY_LOCAL_MACHINE, kDef)
                                           ? "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features"
                                           : "Defender key not present")));

        auto exclusions = reg::enumStringValues(
            HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths");
        bool noExclusions = exclusions.empty();
        out.push_back(make("defender.exclusions", "Defender path exclusions", noExclusions,
                           noExclusions ? "none" : fmtU64(exclusions.size()) + " configured",
                           noExclusions ? ""
                                        : "Review each exclusion. Adding an exclusion is a common "
                                          "way for an intruder to create a safe staging directory.",
                           "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"));
    }

    // ---- Firewall ------------------------------------------------------
    {
        struct Profile { const wchar_t* key; const char* name; };
        const Profile kProfiles[] = {
            {L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile", "domain"},
            {L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\StandardProfile", "private"},
            {L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile", "public"},
        };
        const wchar_t* kFallback =
            L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy";

        for (const Profile& p : kProfiles) {
            DWORD enabled = dwordOr(HKEY_LOCAL_MACHINE, p.key, L"EnableFirewall", 0xFFFFFFFF);
            if (enabled == 0xFFFFFFFF) {
                std::wstring alt = std::wstring(kFallback) + L"\\" +
                                   (std::string(p.name) == "domain"    ? L"DomainProfile"
                                    : std::string(p.name) == "private" ? L"StandardProfile"
                                                                       : L"PublicProfile");
                enabled = dwordOr(HKEY_LOCAL_MACHINE, alt.c_str(), L"EnableFirewall", 1);
            }
            bool on = enabled != 0;
            out.push_back(make(std::string("firewall.") + p.name,
                               std::string("Windows Firewall (") + p.name + " profile)", on,
                               on ? "enabled" : "disabled",
                               on ? "" : "Enable the firewall for this profile.",
                               "FirewallPolicy registry"));
        }
    }

    // ---- Platform integrity --------------------------------------------
    {
        DWORD secureBoot = dwordOr(HKEY_LOCAL_MACHINE,
                                   L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                                   L"UEFISecureBootEnabled", 0xFFFFFFFF);
        bool  known      = secureBoot != 0xFFFFFFFF;
        bool  on         = known && secureBoot == 1;
        out.push_back(make("boot.secureboot", "UEFI Secure Boot", on,
                           !known ? "unknown (legacy BIOS or key absent)"
                                  : (on ? "enabled" : "disabled"),
                           on ? "" : "Enable Secure Boot in firmware to block bootkits and "
                                     "unsigned early-boot drivers.",
                           "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State"));

        DWORD ppl = dwordOr(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                            L"RunAsPPL", 0);
        bool  pplOn = ppl != 0;
        out.push_back(make("lsa.ppl", "LSASS protected process (RunAsPPL)", pplOn,
                           pplOn ? "enabled" : "disabled",
                           pplOn ? "" : "Set RunAsPPL=1 so credential-dumping tools cannot open a "
                                        "handle to LSASS memory.",
                           "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL"));

        DWORD credGuard = dwordOr(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                                  L"LsaCfgFlags", 0);
        bool  cgOn      = credGuard != 0;
        out.push_back(make("lsa.credentialguard", "Credential Guard", cgOn,
                           cgOn ? "configured" : "not configured",
                           cgOn ? "" : "Enable Credential Guard on domain-joined hosts to isolate "
                                       "derived credentials in VBS.",
                           "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LsaCfgFlags"));

        DWORD hvci = dwordOr(HKEY_LOCAL_MACHINE,
                             L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\"
                             L"HypervisorEnforcedCodeIntegrity",
                             L"Enabled", 0);
        bool hvciOn = hvci != 0;
        out.push_back(make("deviceguard.hvci", "Memory integrity (HVCI)", hvciOn,
                           hvciOn ? "enabled" : "disabled",
                           hvciOn ? "" : "Enable memory integrity to block unsigned kernel code.",
                           "DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"));
    }

    // ---- Legacy protocols and credential exposure ----------------------
    {
        DWORD smb1 = dwordOr(HKEY_LOCAL_MACHINE,
                             L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                             L"SMB1", 0xFFFFFFFF);
        bool smb1Off = (smb1 == 0);
        out.push_back(make("smb.v1", "SMBv1 server", smb1Off,
                           smb1Off ? "disabled" : (smb1 == 0xFFFFFFFF ? "default (check feature state)" : "enabled"),
                           smb1Off ? "" : "Remove the SMB1 feature; it is unauthenticated, "
                                          "unencrypted, and the vector for EternalBlue-class worms.",
                           "LanmanServer\\Parameters\\SMB1"));

        DWORD wdigest = dwordOr(HKEY_LOCAL_MACHINE,
                                L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
                                L"UseLogonCredential", 0);
        bool wdOk = (wdigest == 0);
        out.push_back(make("lsa.wdigest", "WDigest cleartext credentials", wdOk,
                           wdOk ? "not cached" : "cached in memory",
                           wdOk ? "" : "Set UseLogonCredential=0; a value of 1 puts plaintext "
                                       "passwords back into LSASS memory.",
                           "SecurityProviders\\WDigest\\UseLogonCredential"));

        DWORD nla = dwordOr(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                            L"UserAuthentication", 1);
        DWORD rdpDenied = dwordOr(HKEY_LOCAL_MACHINE,
                                  L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
                                  L"fDenyTSConnections", 1);
        bool rdpSafe = (rdpDenied != 0) || (nla != 0);
        out.push_back(make("rdp.nla", "RDP network level authentication", rdpSafe,
                           rdpDenied ? "RDP disabled" : (nla ? "NLA required" : "NLA not required"),
                           rdpSafe ? "" : "Require NLA so unauthenticated clients cannot reach the "
                                          "RDP session host.",
                           "Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication"));
    }

    // ---- User Account Control ------------------------------------------
    {
        const wchar_t* kSys = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
        DWORD  enableLua      = dwordOr(HKEY_LOCAL_MACHINE, kSys, L"EnableLUA", 1);
        DWORD  consentAdmin   = dwordOr(HKEY_LOCAL_MACHINE, kSys, L"ConsentPromptBehaviorAdmin", 5);
        bool   uacOn          = enableLua != 0;
        bool   promptStrong   = consentAdmin >= 2;
        out.push_back(make("uac.enabled", "User Account Control", uacOn && promptStrong,
                           !uacOn ? "disabled" : (promptStrong ? "enabled" : "enabled, prompts weakened"),
                           (uacOn && promptStrong)
                               ? ""
                               : "Restore UAC to the default prompt level; auto-elevation removes "
                                 "the last barrier to silent privilege escalation.",
                           "Policies\\System\\EnableLUA"));
    }

    // ---- Audit and telemetry -------------------------------------------
    {
        const wchar_t* kPsBlock =
            L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging";
        bool psLog = dwordOr(HKEY_LOCAL_MACHINE, kPsBlock, L"EnableScriptBlockLogging", 0) != 0;
        out.push_back(make("powershell.scriptblock", "PowerShell script block logging", psLog,
                           psLog ? "enabled" : "disabled",
                           psLog ? "" : "Enable script block logging: without it, obfuscated "
                                        "PowerShell leaves almost no forensic trace.",
                           "Policies\\...\\ScriptBlockLogging"));

        bool cmdAudit = dwordOr(HKEY_LOCAL_MACHINE,
                                L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Audit",
                                L"ProcessCreationIncludeCmdLine_Enabled", 0) != 0;
        out.push_back(make("audit.cmdline", "Command line in process-creation events", cmdAudit,
                           cmdAudit ? "enabled" : "disabled",
                           cmdAudit ? "" : "Enable command-line auditing so 4688 events record what "
                                           "was actually executed.",
                           "Session Manager\\Audit"));

        bool asr = reg::keyExists(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules");
        out.push_back(make("defender.asr", "Attack surface reduction rules", asr,
                           asr ? "configured" : "not configured",
                           asr ? "" : "Configure ASR rules; they block entire classes of Office and "
                                      "script-based initial access.",
                           "Exploit Guard\\ASR\\Rules"));
    }

    // ---- Autorun exposure ----------------------------------------------
    {
        bool autorunOff =
            dwordOr(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                    L"NoDriveTypeAutoRun", 0) >= 0xFF;
        out.push_back(make("explorer.autorun", "Removable-media AutoRun", autorunOff,
                           autorunOff ? "disabled" : "enabled for some drive types",
                           autorunOff ? "" : "Set NoDriveTypeAutoRun to 0xFF to stop removable "
                                             "media from launching code automatically.",
                           "Policies\\Explorer\\NoDriveTypeAutoRun"));

        bool ifeoPresent = valuePresent(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs");
        std::string appInit;
        reg::readString(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                        L"AppInit_DLLs", appInit);
        bool clean = appInit.empty();
        out.push_back(make("windows.appinit", "AppInit_DLLs injection hook", clean,
                           clean ? "empty" : appInit,
                           clean ? "" : "AppInit_DLLs loads the listed library into nearly every "
                                        "GUI process. Verify every entry.",
                           "Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs"));
        (void)ifeoPresent;
    }

    return out;
}

}  // namespace shiranui::platform

#endif  // _WIN32
