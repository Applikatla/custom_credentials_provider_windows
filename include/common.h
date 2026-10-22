#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <unknwn.h>
#include <credentialprovider.h>
#include <string>

// Safe COM Release template
template <class T>
inline void SafeRelease(T** ppT) {
    if (ppT != nullptr && *ppT != nullptr) {
        (*ppT)->Release();
        *ppT = nullptr;
    }
}

// Global DLL reference counter
extern LONG g_cRef;

// Helper to allocate CoTaskMem strings for COM / LogonUI callers
inline HRESULT CoTaskMemAllocString(const std::wstring& source, wchar_t** ppDest) {
    if (ppDest == nullptr) return E_POINTER;
    *ppDest = nullptr;

    size_t length = source.length() + 1;
    size_t byteCount = length * sizeof(wchar_t);
    wchar_t* dest = static_cast<wchar_t*>(CoTaskMemAlloc(byteCount));
    if (dest == nullptr) {
        return E_OUTOFMEMORY;
    }
    wcscpy_s(dest, length, source.c_str());
    *ppDest = dest;
    return S_OK;
}
