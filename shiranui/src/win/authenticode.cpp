// SPDX-License-Identifier: MIT
#ifdef _WIN32

#include "shiranui/win/winutil.hpp"

#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <cstdio>
#include <vector>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace shiranui::platform {

namespace {

std::string certNameOf(PCCERT_CONTEXT cert, DWORD type) {
    DWORD need = ::CertGetNameStringW(cert, type, 0, nullptr, nullptr, 0);
    if (need <= 1) return {};
    std::wstring buf(need, L'\0');
    ::CertGetNameStringW(cert, type, 0, nullptr, buf.data(), need);
    buf.resize(::wcsnlen(buf.c_str(), buf.size()));
    return wideToUtf8(buf);
}

std::string thumbprintOf(PCCERT_CONTEXT cert) {
    BYTE  hash[20];
    DWORD size = sizeof hash;
    if (!::CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, hash, &size)) return {};
    return toHex(ByteView(hash, size), true);
}

/// Pulls the signer certificate out of the embedded PKCS#7 blob.
void extractSigner(const fs::path& file, SignatureResult& out) {
    HCERTSTORE  store = nullptr;
    HCRYPTMSG   msg   = nullptr;
    DWORD       encoding = 0, contentType = 0, formatType = 0;

    if (!::CryptQueryObject(CERT_QUERY_OBJECT_FILE, file.c_str(),
                            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                            CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &contentType, &formatType,
                            &store, &msg, nullptr)) {
        return;
    }
    auto guard = makeGuard([&] {
        if (msg) ::CryptMsgClose(msg);
        if (store) ::CertCloseStore(store, 0);
    });

    DWORD infoSize = 0;
    if (!::CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &infoSize) || infoSize == 0)
        return;
    std::vector<BYTE> buffer(infoSize);
    if (!::CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, buffer.data(), &infoSize)) return;

    auto* signer = reinterpret_cast<CMSG_SIGNER_INFO*>(buffer.data());
    CERT_INFO certInfo{};
    certInfo.Issuer       = signer->Issuer;
    certInfo.SerialNumber = signer->SerialNumber;

    PCCERT_CONTEXT cert = ::CertFindCertificateInStore(
        store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &certInfo,
        nullptr);
    if (!cert) return;
    auto certGuard = makeGuard([&] { ::CertFreeCertificateContext(cert); });

    out.signerName = certNameOf(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE);
    out.thumbprint = thumbprintOf(cert);

    SYSTEMTIME st{};
    FILETIME   ft = cert->pCertInfo->NotAfter;
    if (::FileTimeToSystemTime(&ft, &st)) {
        char buf[32];
        std::snprintf(buf, sizeof buf, "%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
        out.timestamp = std::string("valid until ") + buf;
    }
}

}  // namespace

SignatureResult verifyAuthenticode(const fs::path& file) {
    SignatureResult result;

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct      = sizeof fileInfo;
    fileInfo.pcwszFilePath = file.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA data{};
    data.cbStruct            = sizeof data;
    data.dwUIChoice          = WTD_UI_NONE;
    // Revocation checking is deliberately off by default: it performs network
    // I/O per file, which turns a full-disk scan into an outbound traffic storm
    // and stalls on isolated hosts. `shiranui scan --check-revocation` opts in.
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice       = WTD_CHOICE_FILE;
    data.pFile               = &fileInfo;
    data.dwStateAction       = WTD_STATEACTION_VERIFY;
    data.dwProvFlags         = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG status = ::WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    ::WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);

    switch (status) {
        case ERROR_SUCCESS:
            result.valid   = true;
            result.present = true;
            result.status  = "trusted";
            break;
        case TRUST_E_NOSIGNATURE: {
            DWORD last = ::GetLastError();
            result.present = false;
            result.status  = (last == static_cast<DWORD>(TRUST_E_NOSIGNATURE) ||
                              last == static_cast<DWORD>(TRUST_E_SUBJECT_FORM_UNKNOWN) ||
                              last == static_cast<DWORD>(TRUST_E_PROVIDER_UNKNOWN))
                                 ? "unsigned"
                                 : "signature could not be read";
            break;
        }
        case TRUST_E_EXPLICIT_DISTRUST:
            result.present = true;
            result.status  = "explicitly distrusted by policy";
            break;
        case TRUST_E_SUBJECT_NOT_TRUSTED:
            result.present = true;
            result.status  = "signature present but not trusted";
            break;
        case CRYPT_E_SECURITY_SETTINGS:
            result.present = true;
            result.status  = "blocked by local security settings";
            break;
        case static_cast<LONG>(TRUST_E_BAD_DIGEST):
            result.present = true;
            result.status  = "signature does not match file contents (tampered)";
            break;
        case static_cast<LONG>(CERT_E_EXPIRED):
            result.present = true;
            result.status  = "signing certificate has expired";
            break;
        case static_cast<LONG>(CERT_E_REVOKED):
            result.present = true;
            result.status  = "signing certificate was revoked";
            break;
        default:
            result.present = true;
            result.status  = "verification failed (0x" + fmtHex(static_cast<u64>(static_cast<u32>(status)), 8) + ")";
            break;
    }

    if (result.present) extractSigner(file, result);
    return result;
}

}  // namespace shiranui::platform

#endif  // _WIN32
