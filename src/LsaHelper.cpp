#include "LsaHelper.h"
#include <security.h>
#include <ntsecapi.h>

#ifndef HRESULT_FROM_NT
#define HRESULT_FROM_NT(nt) ((HRESULT) ((nt) | 0x10000000))
#endif

namespace LsaHelper {

HRESULT GetAuthenticationPackage(ULONG* pulAuthPackage) {
    if (pulAuthPackage == nullptr) return E_POINTER;
    *pulAuthPackage = 0;

    HANDLE hLsa = nullptr;
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (status != 0) { // STATUS_SUCCESS = 0
        return HRESULT_FROM_NT(status);
    }

    LSA_STRING packageName = {};
    packageName.Buffer = const_cast<PCHAR>(MICROSOFT_KERBEROS_NAME_A);
    packageName.Length = static_cast<USHORT>(strlen(MICROSOFT_KERBEROS_NAME_A));
    packageName.MaximumLength = packageName.Length + 1;

    status = LsaLookupAuthenticationPackage(hLsa, &packageName, pulAuthPackage);
    LsaDeregisterLogonProcess(hLsa);

    if (status != 0) {
        return HRESULT_FROM_NT(status);
    }

    return S_OK;
}

void SplitUsernameAndDomain(const std::wstring& fullInput, 
                            std::wstring& outUsername, 
                            std::wstring& outDomain) {
    // Check for "DOMAIN\Username" format
    size_t backslashPos = fullInput.find(L'\\');
    if (backslashPos != std::wstring::npos) {
        outDomain = fullInput.substr(0, backslashPos);
        outUsername = fullInput.substr(backslashPos + 1);
        return;
    }

    // Check for "User@domain.com" format (UPN)
    size_t atPos = fullInput.find(L'@');
    if (atPos != std::wstring::npos) {
        outUsername = fullInput.substr(0, atPos);
        outDomain = fullInput.substr(atPos + 1);
        return;
    }

    // Default: local user, empty domain
    outUsername = fullInput;
    outDomain = L"";
}

HRESULT PackKerbInteractiveLogon(
    const std::wstring& username,
    const std::wstring& domain,
    const std::wstring& password,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    BYTE** ppbSerialization,
    ULONG* pcbSerialization) 
{
    if (ppbSerialization == nullptr || pcbSerialization == nullptr) return E_POINTER;
    *ppbSerialization = nullptr;
    *pcbSerialization = 0;

    const ULONG cbDomain = static_cast<ULONG>(domain.length() * sizeof(wchar_t));
    const ULONG cbUser = static_cast<ULONG>(username.length() * sizeof(wchar_t));
    const ULONG cbPassword = static_cast<ULONG>(password.length() * sizeof(wchar_t));

    const ULONG cbTotal = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + cbDomain + cbUser + cbPassword;

    // CoTaskMemAlloc is mandatory because LogonUI will free this memory with CoTaskMemFree
    BYTE* pBuffer = static_cast<BYTE*>(CoTaskMemAlloc(cbTotal));
    if (pBuffer == nullptr) {
        return E_OUTOFMEMORY;
    }
    ZeroMemory(pBuffer, cbTotal);

    KERB_INTERACTIVE_UNLOCK_LOGON* pUnlockLogon = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(pBuffer);

    // Set message type depending on whether workstation is being unlocked or fresh logon
    if (cpus == CPUS_UNLOCK_WORKSTATION) {
        pUnlockLogon->Logon.MessageType = KerbWorkstationUnlockLogon;
    } else {
        pUnlockLogon->Logon.MessageType = KerbInteractiveLogon;
    }

    BYTE* pCurrent = pBuffer + sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);

    // 1. Pack Domain string
    pUnlockLogon->Logon.LogonDomainName.Length = static_cast<USHORT>(cbDomain);
    pUnlockLogon->Logon.LogonDomainName.MaximumLength = static_cast<USHORT>(cbDomain);
    if (cbDomain > 0) {
        CopyMemory(pCurrent, domain.c_str(), cbDomain);
        pUnlockLogon->Logon.LogonDomainName.Buffer = reinterpret_cast<PWSTR>(pCurrent);
        pCurrent += cbDomain;
    } else {
        pUnlockLogon->Logon.LogonDomainName.Buffer = nullptr;
    }

    // 2. Pack Username string
    pUnlockLogon->Logon.UserName.Length = static_cast<USHORT>(cbUser);
    pUnlockLogon->Logon.UserName.MaximumLength = static_cast<USHORT>(cbUser);
    if (cbUser > 0) {
        CopyMemory(pCurrent, username.c_str(), cbUser);
        pUnlockLogon->Logon.UserName.Buffer = reinterpret_cast<PWSTR>(pCurrent);
        pCurrent += cbUser;
    } else {
        pUnlockLogon->Logon.UserName.Buffer = nullptr;
    }

    // 3. Pack Password string
    pUnlockLogon->Logon.Password.Length = static_cast<USHORT>(cbPassword);
    pUnlockLogon->Logon.Password.MaximumLength = static_cast<USHORT>(cbPassword);
    if (cbPassword > 0) {
        CopyMemory(pCurrent, password.c_str(), cbPassword);
        pUnlockLogon->Logon.Password.Buffer = reinterpret_cast<PWSTR>(pCurrent);
        pCurrent += cbPassword;
    } else {
        pUnlockLogon->Logon.Password.Buffer = nullptr;
    }

    *ppbSerialization = pBuffer;
    *pcbSerialization = cbTotal;
    return S_OK;
}

} // namespace LsaHelper
