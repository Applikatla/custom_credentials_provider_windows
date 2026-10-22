#include "common.h"
#include "guid.h"
#include "ClassFactory.h"

HINSTANCE g_hInst = nullptr;
LONG g_cRef = 0;

static const wchar_t c_szClsidString[] = L"{3A4E2F6C-81D5-4F8A-9A8E-2B6C7D8E9F01}";
static const wchar_t c_szProviderName[] = L"Custom MFA Credential Provider";

// -----------------------------------------------------------------------------
// DLL Entry Point
// -----------------------------------------------------------------------------

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        g_hInst = hModule;
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

// -----------------------------------------------------------------------------
// COM Exports
// -----------------------------------------------------------------------------

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (ppv == nullptr) return E_POINTER;
    *ppv = nullptr;

    if (!IsEqualCLSID(rclsid, CLSID_MfaCredentialProvider)) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    ClassFactory* pFactory = new ClassFactory();
    if (pFactory == nullptr) {
        return E_OUTOFMEMORY;
    }

    HRESULT hr = pFactory->QueryInterface(riid, ppv);
    pFactory->Release();
    return hr;
}

STDAPI DllCanUnloadNow() {
    return (g_cRef == 0) ? S_OK : S_FALSE;
}

// -----------------------------------------------------------------------------
// Self-Registration & Unregistration (regsvr32)
// -----------------------------------------------------------------------------

static HRESULT SetRegistryString(HKEY hRoot, const wchar_t* subKey, const wchar_t* valueName, const wchar_t* data) {
    HKEY hKey = nullptr;
    LSTATUS status = RegCreateKeyExW(
        hRoot, subKey, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr
    );
    if (status != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(status);
    }

    status = RegSetValueExW(
        hKey, valueName, 0, REG_SZ, 
        reinterpret_cast<const BYTE*>(data), 
        static_cast<DWORD>((wcslen(data) + 1) * sizeof(wchar_t))
    );
    RegCloseKey(hKey);
    return HRESULT_FROM_WIN32(status);
}

STDAPI DllRegisterServer() {
    wchar_t szModulePath[MAX_PATH] = {};
    if (GetModuleFileNameW(g_hInst, szModulePath, MAX_PATH) == 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // 1. Register in HKCR\CLSID\{GUID}
    std::wstring clsidKey = std::wstring(L"CLSID\\") + c_szClsidString;
    HRESULT hr = SetRegistryString(HKEY_CLASSES_ROOT, clsidKey.c_str(), nullptr, c_szProviderName);
    if (FAILED(hr)) return hr;

    // 2. Set InprocServer32 path & ThreadingModel
    std::wstring inprocKey = clsidKey + L"\\InprocServer32";
    hr = SetRegistryString(HKEY_CLASSES_ROOT, inprocKey.c_str(), nullptr, szModulePath);
    if (FAILED(hr)) return hr;

    hr = SetRegistryString(HKEY_CLASSES_ROOT, inprocKey.c_str(), L"ThreadingModel", L"Apartment");
    if (FAILED(hr)) return hr;

    // 3. Register as an active Windows Credential Provider in HKLM
    std::wstring cpKey = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\") + c_szClsidString;
    hr = SetRegistryString(HKEY_LOCAL_MACHINE, cpKey.c_str(), nullptr, c_szProviderName);
    if (FAILED(hr)) return hr;

    return S_OK;
}

STDAPI DllUnregisterServer() {
    // 1. Remove from Windows Credential Providers in HKLM
    std::wstring cpKey = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\") + c_szClsidString;
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, cpKey.c_str());

    // 2. Remove InprocServer32 and CLSID from HKCR
    std::wstring inprocKey = std::wstring(L"CLSID\\") + c_szClsidString + L"\\InprocServer32";
    RegDeleteKeyW(HKEY_CLASSES_ROOT, inprocKey.c_str());

    std::wstring clsidKey = std::wstring(L"CLSID\\") + c_szClsidString;
    RegDeleteKeyW(HKEY_CLASSES_ROOT, clsidKey.c_str());

    return S_OK;
}
