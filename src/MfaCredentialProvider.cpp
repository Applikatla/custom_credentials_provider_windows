#include "MfaCredentialProvider.h"
#include <shlwapi.h>

// Helper to copy a field descriptor using CoTaskMemAlloc for LogonUI
static HRESULT CopyFieldDescriptor(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& src, 
                                   CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppDest) {
    if (ppDest == nullptr) return E_POINTER;
    *ppDest = nullptr;

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pDest = 
        static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
    if (pDest == nullptr) {
        return E_OUTOFMEMORY;
    }

    *pDest = src;
    if (src.pszLabel != nullptr) {
        HRESULT hr = CoTaskMemAllocString(src.pszLabel, &pDest->pszLabel);
        if (FAILED(hr)) {
            CoTaskMemFree(pDest);
            return hr;
        }
    } else {
        pDest->pszLabel = nullptr;
    }

    *ppDest = pDest;
    return S_OK;
}

MfaCredentialProvider::MfaCredentialProvider()
    : m_cRef(1)
    , m_cpus(CPUS_INVALID)
    , m_dwFlags(0)
    , m_pEvents(nullptr)
    , m_upAdviseContext(0)
    , m_pCredential(nullptr) 
{
    InterlockedIncrement(&g_cRef);
}

MfaCredentialProvider::~MfaCredentialProvider() {
    SafeRelease(&m_pCredential);
    SafeRelease(&m_pEvents);
    InterlockedDecrement(&g_cRef);
}

// -----------------------------------------------------------------------------
// IUnknown
// -----------------------------------------------------------------------------

HRESULT MfaCredentialProvider::QueryInterface(REFIID riid, void** ppv) {
    if (ppv == nullptr) return E_POINTER;
    *ppv = nullptr;

    if (riid == IID_IUnknown || riid == IID_ICredentialProvider) {
        *ppv = static_cast<ICredentialProvider*>(this);
    } else if (riid == IID_ICredentialProvider2) {
        *ppv = static_cast<ICredentialProvider2*>(this);
    } else {
        return E_NOINTERFACE;
    }

    AddRef();
    return S_OK;
}

ULONG MfaCredentialProvider::AddRef() {
    return InterlockedIncrement(&m_cRef);
}

ULONG MfaCredentialProvider::Release() {
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0) {
        delete this;
    }
    return cRef;
}

// -----------------------------------------------------------------------------
// ICredentialProvider
// -----------------------------------------------------------------------------

HRESULT MfaCredentialProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags) {
    m_cpus = cpus;
    m_dwFlags = dwFlags;

    switch (cpus) {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
    case CPUS_CREDUI:
        return S_OK;

    case CPUS_CHANGE_PASSWORD:
    default:
        // Scenario not supported by this provider
        return E_NOTIMPL;
    }
}

HRESULT MfaCredentialProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) {
    UNREFERENCED_PARAMETER(pcpcs);
    // Returning S_OK accepts incoming serialized data if provided (e.g. from CredUI)
    return S_OK;
}

HRESULT MfaCredentialProvider::Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext) {
    if (pcpe == nullptr) return E_POINTER;

    SafeRelease(&m_pEvents);
    m_pEvents = pcpe;
    m_pEvents->AddRef();
    m_upAdviseContext = upAdviseContext;

    return S_OK;
}

HRESULT MfaCredentialProvider::UnAdvise() {
    SafeRelease(&m_pEvents);
    m_upAdviseContext = 0;
    return S_OK;
}

HRESULT MfaCredentialProvider::GetFieldDescriptorCount(DWORD* pdwCount) {
    if (pdwCount == nullptr) return E_POINTER;
    *pdwCount = FIELD_COUNT;
    return S_OK;
}

HRESULT MfaCredentialProvider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) {
    if (ppcpfd == nullptr) return E_POINTER;
    if (dwIndex >= FIELD_COUNT) return E_INVALIDARG;

    return CopyFieldDescriptor(MfaCredential::s_FieldDescriptors[dwIndex], ppcpfd);
}

HRESULT MfaCredentialProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault) {
    if (pdwCount == nullptr || pdwDefault == nullptr || pbAutoLogonWithDefault == nullptr) {
        return E_POINTER;
    }

    // Report 1 credential tile
    *pdwCount = 1;
    *pdwDefault = 0;
    *pbAutoLogonWithDefault = FALSE;
    return S_OK;
}

HRESULT MfaCredentialProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc) {
    if (ppcpc == nullptr) return E_POINTER;
    *ppcpc = nullptr;

    if (dwIndex != 0) return E_INVALIDARG;

    // Lazily instantiate the credential tile if not created yet
    if (m_pCredential == nullptr) {
        m_pCredential = new MfaCredential();
        if (m_pCredential == nullptr) {
            return E_OUTOFMEMORY;
        }
    }

    m_pCredential->SetUsageScenario(m_cpus);

    return m_pCredential->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
}

// -----------------------------------------------------------------------------
// ICredentialProvider2
// -----------------------------------------------------------------------------

HRESULT MfaCredentialProvider::SetUserArray(ICredentialProviderUserArray* users) {
    UNREFERENCED_PARAMETER(users);
    // User array enumeration can be used to tailor the tile to specific users
    return S_OK;
}
