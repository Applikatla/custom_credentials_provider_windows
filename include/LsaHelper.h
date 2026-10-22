#pragma once

#include "common.h"
#include <ntsecapi.h>
#include <string>

namespace LsaHelper {

    // Resolves the LSA Authentication Package ID for Kerberos / Negotiate
    HRESULT GetAuthenticationPackage(ULONG* pulAuthPackage);

    // Splits "DOMAIN\\Username" or "Username@domain.com" into clean username and domain components
    void SplitUsernameAndDomain(const std::wstring& fullInput, 
                                std::wstring& outUsername, 
                                std::wstring& outDomain);

    // Packages credentials into a KERB_INTERACTIVE_UNLOCK_LOGON buffer allocated with CoTaskMemAlloc.
    // This is passed to Windows LSA in GetSerialization() to complete login.
    HRESULT PackKerbInteractiveLogon(
        const std::wstring& username,
        const std::wstring& domain,
        const std::wstring& password,
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        BYTE** ppbSerialization,
        ULONG* pcbSerialization
    );

} // namespace LsaHelper
