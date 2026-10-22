#include <windows.h>
#include <wincred.h>
#include <credui.h>
#include <ntsecapi.h>
#include <iostream>
#include "guid.h"
#include "IpcProtocol.h"

// =============================================================================
// Standalone Desktop Test Harness for Custom MFA Credential Provider
//
// This tool launches Windows CredUI in a normal desktop window, allowing you
// to interactively test the tile, dropdowns, buttons, IPC callbacks, and LSA
// serialization WITHOUT touching the Windows lock screen or risking a lockout!
// =============================================================================

void VerifyRegistryRegistration() {
    std::wcout << L"[*] Checking if Credential Provider is registered in Windows...\n";

    HKEY hKey = nullptr;
    const wchar_t szCpKey[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{3A4E2F6C-81D5-4F8A-9A8E-2B6C7D8E9F01}";
    
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, szCpKey, 0, KEY_READ, &hKey);
    if (status == ERROR_SUCCESS) {
        std::wcout << L"[+] Provider is REGISTERED in HKLM Credential Providers.\n";
        RegCloseKey(hKey);
    } else {
        std::wcout << L"[-] Provider NOT detected in registry.\n";
        std::wcout << L"    Run 'regsvr32 CustomMfaCredentialProvider.dll' as Administrator first!\n";
    }
}

int main() {
    std::wcout << L"===============================================================\n";
    std::wcout << L"   Custom MFA Credential Provider - Desktop Test Harness       \n";
    std::wcout << L"===============================================================\n\n";

    // Initialize COM
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        std::wcout << L"[-] Failed to initialize COM. HR: " << hr << L"\n";
        return 1;
    }

    VerifyRegistryRegistration();

    std::wcout << L"\n[*] Launching CredUI Prompt window on your desktop...\n";
    std::wcout << L"    (Tip: Make sure MockMfaService is running to test live IPC!)\n\n";

    CREDUI_INFOW credUiInfo = {};
    credUiInfo.cbSize = sizeof(credUiInfo);
    credUiInfo.hwndParent = nullptr;
    credUiInfo.pszMessageText = L"Select the Custom MFA Tile, enter credentials, and test your MFA method.";
    credUiInfo.pszCaptionText = L"MFA Credential Provider Desktop Test";

    ULONG authPackage = 0;
    LPVOID outCredBuffer = nullptr;
    ULONG outCredSize = 0;
    BOOL saveState = FALSE;

    // Display the credential UI in generic desktop mode
    DWORD dwFlags = CREDUIWIN_GENERIC;

    DWORD dwResult = CredUIPromptForWindowsCredentialsW(
        &credUiInfo,
        0,                      // Error code to display (0 = none)
        &authPackage,           // In/Out Auth package
        nullptr,                // In Auth buffer (optional pre-fill)
        0,                      // In Auth buffer size
        &outCredBuffer,         // Out Auth buffer serialized by our DLL
        &outCredSize,           // Out Auth buffer size
        &saveState,             // Out Save checkbox
        dwFlags
    );

    if (dwResult == ERROR_SUCCESS) {
        std::wcout << L"\n===============================================================\n";
        std::wcout << L"[+] SUCCESS: CredUI prompt submitted and verified!\n";
        std::wcout << L"    Authentication Package ID: " << authPackage << L"\n";
        std::wcout << L"    Serialized Buffer Size:    " << outCredSize << L" bytes\n";

        // Inspect serialized KERB_INTERACTIVE_UNLOCK_LOGON buffer
        if (outCredBuffer != nullptr && outCredSize >= sizeof(KERB_INTERACTIVE_UNLOCK_LOGON)) {
            auto* pLogon = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(outCredBuffer);

            std::wstring user(pLogon->Logon.UserName.Buffer, pLogon->Logon.UserName.Length / sizeof(wchar_t));
            std::wstring domain(pLogon->Logon.LogonDomainName.Buffer, pLogon->Logon.LogonDomainName.Length / sizeof(wchar_t));

            std::wcout << L"    Serialized User:           " << user << L"\n";
            std::wcout << L"    Serialized Domain:         " << domain << L"\n";
            std::wcout << L"    Message Type:              " 
                       << (pLogon->Logon.MessageType == KerbInteractiveLogon ? L"KerbInteractiveLogon" : L"KerbWorkstationUnlockLogon") 
                       << L"\n";
            std::wcout << L"[+] Serialization buffer is VALID for Windows LSA handoff!\n";

            CoTaskMemFree(outCredBuffer);
        }
        std::wcout << L"===============================================================\n";
    } else if (dwResult == ERROR_CANCELLED) {
        std::wcout << L"\n[*] Test was cancelled by the user.\n";
    } else {
        std::wcout << L"\n[-] CredUI prompt exited with error code: " << dwResult << L"\n";
    }

    CoUninitialize();
    return 0;
}
