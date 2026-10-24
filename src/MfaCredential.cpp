#include "MfaCredential.h"
#include "guid.h"
#include "LsaHelper.h"
#include <shlwapi.h>

// Static Field Descriptors: Defines the UI layout of the credential tile
const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR MfaCredential::s_FieldDescriptors[FIELD_COUNT] = {
    { FIELD_TILE_IMAGE,   CPFT_TILE_IMAGE,    L"Avatar",           CPFG_LOGON_PASSWORD },
    { FIELD_LABEL,        CPFT_LARGE_TEXT,    L"MFA Login",        CPFG_LOGON_PASSWORD },
    { FIELD_USERNAME,     CPFT_EDIT_TEXT,     L"Username",         CPFG_LOGON_PASSWORD },
    { FIELD_PASSWORD,     CPFT_PASSWORD_TEXT, L"Password",         CPFG_LOGON_PASSWORD },
    { FIELD_MFA_METHOD,   CPFT_COMBOBOX,      L"MFA Method",       CPFG_LOGON_PASSWORD },
    { FIELD_MFA_PAYLOAD,  CPFT_EDIT_TEXT,     L"Code / PIN",       CPFG_LOGON_PASSWORD },
    { FIELD_STATUS_TEXT,  CPFT_SMALL_TEXT,    L"Status",           CPFG_LOGON_PASSWORD },
    { FIELD_SUBMIT_BUTTON,CPFT_SUBMIT_BUTTON, L"Submit",           CPFG_LOGON_PASSWORD },
};

MfaCredential::MfaCredential()
    : m_cRef(1)
    , m_pEvents(nullptr)
    , m_selectedMfaMethodIndex(0)
    , m_statusText(L"Please enter your credentials.")
    , m_cpus(CPUS_INVALID) 
{
    InterlockedIncrement(&g_cRef);

    // Populate selectable MFA options
    m_mfaMethods.push_back({ L"TOTP (Authenticator App)",      MfaMethod::Totp });
    m_mfaMethods.push_back({ L"Security Key (Passkey / FIDO2)", MfaMethod::Passkey });
    m_mfaMethods.push_back({ L"Biometric (Fingerprint / Face)", MfaMethod::Biometric });
    m_mfaMethods.push_back({ L"Smart Card",                    MfaMethod::SmartCard });
    m_mfaMethods.push_back({ L"Mobile Push Notification",      MfaMethod::Push });
}

MfaCredential::~MfaCredential() {
    SafeRelease(&m_pEvents);
    InterlockedDecrement(&g_cRef);
}

// -----------------------------------------------------------------------------
// IUnknown
// -----------------------------------------------------------------------------

HRESULT MfaCredential::QueryInterface(REFIID riid, void** ppv) {
    if (ppv == nullptr) return E_POINTER;
    *ppv = nullptr;

    if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential) {
        *ppv = static_cast<ICredentialProviderCredential*>(this);
    } else if (riid == IID_ICredentialProviderCredential2) {
        *ppv = static_cast<ICredentialProviderCredential2*>(this);
    } else if (riid == IID_ICredentialProviderCredentialWithFieldOptions) {
        *ppv = static_cast<ICredentialProviderCredentialWithFieldOptions*>(this);
    } else {
        return E_NOINTERFACE;
    }

    AddRef();
    return S_OK;
}

ULONG MfaCredential::AddRef() {
    return InterlockedIncrement(&m_cRef);
}

ULONG MfaCredential::Release() {
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0) {
        delete this;
    }
    return cRef;
}

// -----------------------------------------------------------------------------
// ICredentialProviderCredential
// -----------------------------------------------------------------------------

HRESULT MfaCredential::Advise(ICredentialProviderCredentialEvents* pcpce) {
    if (pcpce == nullptr) return E_POINTER;
    SafeRelease(&m_pEvents);
    m_pEvents = pcpce;
    m_pEvents->AddRef();
    return S_OK;
}

HRESULT MfaCredential::UnAdvise() {
    SafeRelease(&m_pEvents);
    return S_OK;
}

HRESULT MfaCredential::SetSelected(BOOL* pbAutoLogon) {
    if (pbAutoLogon == nullptr) return E_POINTER;
    *pbAutoLogon = FALSE;
    return S_OK;
}

HRESULT MfaCredential::SetDeselected() {
    return S_OK;
}

HRESULT MfaCredential::GetFieldState(DWORD dwFieldID, 
                                     CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, 
                                     CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) {
    if (pcpfs == nullptr) return E_POINTER;

    // Default interactive state
    if (pcpfis != nullptr) {
        *pcpfis = CPFIS_NONE;
    }

    switch (dwFieldID) {
    case FIELD_TILE_IMAGE:
    case FIELD_LABEL:
        *pcpfs = CPFS_DISPLAY_IN_BOTH;
        break;

    case FIELD_USERNAME:
    case FIELD_PASSWORD:
    case FIELD_MFA_METHOD:
    case FIELD_STATUS_TEXT:
    case FIELD_SUBMIT_BUTTON:
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        if (dwFieldID == FIELD_USERNAME && pcpfis != nullptr) {
            *pcpfis = CPFIS_FOCUSED;
        }
        break;

    case FIELD_MFA_PAYLOAD:
        // Only display the text input if TOTP or SmartCard PIN is chosen.
        // For Biometric, Passkey, or Push, the payload box is hidden.
        if (m_mfaMethods[m_selectedMfaMethodIndex].second == MfaMethod::Totp ||
            m_mfaMethods[m_selectedMfaMethodIndex].second == MfaMethod::SmartCard) {
            *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        } else {
            *pcpfs = CPFS_HIDDEN;
        }
        break;

    default:
        return E_INVALIDARG;
    }

    return S_OK;
}

HRESULT MfaCredential::GetStringValue(DWORD dwFieldID, PWSTR* ppsz) {
    if (ppsz == nullptr) return E_POINTER;
    *ppsz = nullptr;

    switch (dwFieldID) {
    case FIELD_LABEL:
        return CoTaskMemAllocString(L"Custom MFA Login", ppsz);

    case FIELD_USERNAME:
        return CoTaskMemAllocString(m_username, ppsz);

    case FIELD_PASSWORD:
        return CoTaskMemAllocString(m_password, ppsz);

    case FIELD_MFA_PAYLOAD:
        return CoTaskMemAllocString(m_mfaPayload, ppsz);

    case FIELD_STATUS_TEXT:
        return CoTaskMemAllocString(m_statusText, ppsz);

    default:
        return E_INVALIDARG;
    }
}

HRESULT MfaCredential::SetStringValue(DWORD dwFieldID, PCWSTR psz) {
    if (psz == nullptr) return E_POINTER;

    switch (dwFieldID) {
    case FIELD_USERNAME:
        m_username = psz;
        break;

    case FIELD_PASSWORD:
        m_password = psz;
        break;

    case FIELD_MFA_PAYLOAD:
        m_mfaPayload = psz;
        break;

    default:
        return E_INVALIDARG;
    }

    return S_OK;
}

HRESULT MfaCredential::GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppszLabel) {
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pbChecked);
    UNREFERENCED_PARAMETER(ppszLabel);
    return E_NOTIMPL;
}

HRESULT MfaCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked) {
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);
    return E_NOTIMPL;
}

HRESULT MfaCredential::GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem) {
    if (dwFieldID != FIELD_MFA_METHOD) return E_INVALIDARG;
    if (pcItems == nullptr || pdwSelectedItem == nullptr) return E_POINTER;

    *pcItems = static_cast<DWORD>(m_mfaMethods.size());
    *pdwSelectedItem = m_selectedMfaMethodIndex;
    return S_OK;
}

HRESULT MfaCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppszItem) {
    if (dwFieldID != FIELD_MFA_METHOD) return E_INVALIDARG;
    if (ppszItem == nullptr) return E_POINTER;
    if (dwItem >= m_mfaMethods.size()) return E_INVALIDARG;

    return CoTaskMemAllocString(m_mfaMethods[dwItem].first, ppszItem);
}

HRESULT MfaCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem) {
    if (dwFieldID != FIELD_MFA_METHOD) return E_INVALIDARG;
    if (dwSelectedItem >= m_mfaMethods.size()) return E_INVALIDARG;

    m_selectedMfaMethodIndex = dwSelectedItem;
    UpdateMfaFieldVisibility();
    return S_OK;
}

void MfaCredential::UpdateMfaFieldVisibility() {
    if (m_pEvents == nullptr) return;

    // 1. Notify LogonUI of the new visibility state of the MFA payload box
    CREDENTIAL_PROVIDER_FIELD_STATE payloadState = CPFS_HIDDEN;
    if (m_mfaMethods[m_selectedMfaMethodIndex].second == MfaMethod::Totp ||
        m_mfaMethods[m_selectedMfaMethodIndex].second == MfaMethod::SmartCard) {
        payloadState = CPFS_DISPLAY_IN_SELECTED_TILE;
    }
    m_pEvents->SetFieldState(this, FIELD_MFA_PAYLOAD, payloadState);

    // 2. Update status label dynamically depending on method selected
    switch (m_mfaMethods[m_selectedMfaMethodIndex].second) {
    case MfaMethod::Totp:
        SetStatus(L"Enter your 6-digit TOTP code.");
        break;
    case MfaMethod::Passkey:
        SetStatus(L"Click Submit, then touch your security key.");
        break;
    case MfaMethod::Biometric:
        SetStatus(L"Click Submit, then touch the fingerprint/face sensor.");
        break;
    case MfaMethod::SmartCard:
        SetStatus(L"Insert Smart Card and enter your PIN.");
        break;
    case MfaMethod::Push:
        SetStatus(L"Click Submit to send approval push to your phone.");
        break;
    }
}

void MfaCredential::SetStatus(const std::wstring& message) {
    m_statusText = message;
    if (m_pEvents != nullptr) {
        m_pEvents->SetFieldString(this, FIELD_STATUS_TEXT, m_statusText.c_str());
    }
}

HRESULT MfaCredential::CommandLinkClicked(DWORD dwFieldID) {
    UNREFERENCED_PARAMETER(dwFieldID);
    return E_NOTIMPL;
}

HRESULT MfaCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo) {
    if (dwFieldID != FIELD_SUBMIT_BUTTON) return E_INVALIDARG;
    if (pdwAdjacentTo == nullptr) return E_POINTER;

    // Position submit button next to password or MFA payload
    *pdwAdjacentTo = FIELD_PASSWORD;
    return S_OK;
}

HRESULT MfaCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp) {
    if (dwFieldID != FIELD_TILE_IMAGE) return E_INVALIDARG;
    if (phbmp == nullptr) return E_POINTER;
    *phbmp = nullptr; // Windows will render default user avatar if null
    return S_OK;
}

HRESULT MfaCredential::GetFieldOptions(DWORD dwFieldID, CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS* pOptions) {
    if (pOptions == nullptr) return E_POINTER;
    *pOptions = CPCFO_NONE;

    if (dwFieldID == FIELD_PASSWORD) {
        *pOptions = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
    return S_OK;
}

// -----------------------------------------------------------------------------
// Verification Trigger & LSA Serialization
// -----------------------------------------------------------------------------

HRESULT MfaCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr, 
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, 
    PWSTR* ppszOptionalStatusText, 
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) 
{
    if (pcpgsr == nullptr || pcpcs == nullptr) return E_POINTER;
    *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;

    // Validate that username and password are provided
    if (m_username.empty() || m_password.empty()) {
        SetStatus(L"Please enter both username and password.");
        return S_OK;
    }

    SetStatus(L"Contacting MFA Service via IPC...");

    // 1. Call our IPC Client from Step 1!
    MfaMethod selectedMethod = m_mfaMethods[m_selectedMfaMethodIndex].second;
    MfaAuthResponse mfaResult = m_ipcClient.Authenticate(
        m_username,
        L"", // Domain if applicable
        selectedMethod,
        m_mfaPayload,
        [this](const std::wstring& progress) {
            // Live progress updates streamed from the MFA background service!
            SetStatus(progress);
        },
        30000 // 30 second timeout
    );

    // 2. Check the verdict from the MFA service
    if (!mfaResult.isSuccess) {
        // MFA Failed or Timed out
        SetStatus(mfaResult.message);
        if (ppszOptionalStatusText != nullptr) {
            CoTaskMemAllocString(mfaResult.message, ppszOptionalStatusText);
        }
        if (pcpsiOptionalStatusIcon != nullptr) {
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
        }
        // Tell Windows: Authentication failed, stay on the tile so user can retry!
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
        return S_OK;
    }

    // 3. MFA Succeeded!
    SetStatus(L"MFA Verified! Logging in...");

    // 4. Resolve the Kerberos / Negotiate LSA package ID
    ULONG ulAuthPackage = 0;
    HRESULT hr = LsaHelper::GetAuthenticationPackage(&ulAuthPackage);
    if (FAILED(hr)) {
        SetStatus(L"Failed to query LSA Authentication Package.");
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
        return S_OK;
    }

    // 5. Split domain and username (e.g. "CORP\JohnDoe" or "JohnDoe@corp.com")
    std::wstring cleanUser;
    std::wstring domain;
    LsaHelper::SplitUsernameAndDomain(m_username, cleanUser, domain);

    // 6. Build the serialized KERB_INTERACTIVE_UNLOCK_LOGON buffer
    BYTE* pbSerialization = nullptr;
    ULONG cbSerialization = 0;
    hr = LsaHelper::PackKerbInteractiveLogon(
        cleanUser,
        domain,
        m_password,
        m_cpus,
        &pbSerialization,
        &cbSerialization
    );

    if (FAILED(hr)) {
        SetStatus(L"Failed to serialize credentials for LSA.");
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
        return S_OK;
    }

    // 7. Hand off the serialization to Windows LogonUI
    pcpcs->ulAuthenticationPackage = ulAuthPackage;
    pcpcs->clsidCredentialProvider = CLSID_MfaCredentialProvider;
    pcpcs->cbSerialization = cbSerialization;
    pcpcs->rgbSerialization = pbSerialization;

    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    return S_OK;
}

HRESULT MfaCredential::ReportResult(NTSTATUS ntsStatus, 
                                    NTSTATUS ntsSubstatus, 
                                    PWSTR* ppszOptionalStatusText, 
                                    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) {
    UNREFERENCED_PARAMETER(ntsStatus);
    UNREFERENCED_PARAMETER(ntsSubstatus);
    UNREFERENCED_PARAMETER(ppszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);
    return S_OK;
}

// -----------------------------------------------------------------------------
// ICredentialProviderCredential2
// -----------------------------------------------------------------------------

HRESULT MfaCredential::GetUserSid(PWSTR* ppszSid) {
    if (ppszSid == nullptr) return E_POINTER;
    *ppszSid = nullptr; // Return null for generic/domain tiles
    return S_OK;
}
