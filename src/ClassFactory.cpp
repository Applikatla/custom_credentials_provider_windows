#include "ClassFactory.h"
#include "MfaCredentialProvider.h"

ClassFactory::ClassFactory()
    : m_cRef(1) 
{
    InterlockedIncrement(&g_cRef);
}

ClassFactory::~ClassFactory() {
    InterlockedDecrement(&g_cRef);
}

HRESULT ClassFactory::QueryInterface(REFIID riid, void** ppv) {
    if (ppv == nullptr) return E_POINTER;
    *ppv = nullptr;

    if (riid == IID_IUnknown || riid == IID_IClassFactory) {
        *ppv = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }

    return E_NOINTERFACE;
}

ULONG ClassFactory::AddRef() {
    return InterlockedIncrement(&m_cRef);
}

ULONG ClassFactory::Release() {
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0) {
        delete this;
    }
    return cRef;
}

HRESULT ClassFactory::CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) {
    if (ppv == nullptr) return E_POINTER;
    *ppv = nullptr;

    // Aggregation is not supported for Credential Providers
    if (pUnkOuter != nullptr) {
        return CLASS_E_NOAGGREGATION;
    }

    MfaCredentialProvider* pProvider = new MfaCredentialProvider();
    if (pProvider == nullptr) {
        return E_OUTOFMEMORY;
    }

    HRESULT hr = pProvider->QueryInterface(riid, ppv);
    pProvider->Release();
    return hr;
}

HRESULT ClassFactory::LockServer(BOOL fLock) {
    if (fLock) {
        InterlockedIncrement(&g_cRef);
    } else {
        InterlockedDecrement(&g_cRef);
    }
    return S_OK;
}
