#pragma once

#include "common.h"
#include "IpcProtocol.h"
#include "MfaIpcClient.h"
#include <string>
#include <vector>

// Enumeration of all visual fields on our credential tile
enum FieldId {
    FIELD_TILE_IMAGE = 0,
    FIELD_LABEL = 1,
    FIELD_USERNAME = 2,
    FIELD_PASSWORD = 3,
    FIELD_MFA_METHOD = 4,
    FIELD_MFA_PAYLOAD = 5,
    FIELD_STATUS_TEXT = 6,
    FIELD_SUBMIT_BUTTON = 7,
    FIELD_COUNT = 8
};

class MfaCredential : public ICredentialProviderCredential2,
                      public ICredentialProviderCredentialWithFieldOptions {
public:
    MfaCredential();
    virtual ~MfaCredential();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon) override;
    IFACEMETHODIMP SetDeselected() override;
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID, 
                                CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, 
                                CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) override;
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppsz) override;
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, PCWSTR psz) override;
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppszLabel) override;
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked) override;
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem) override;
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppszItem) override;
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem) override;
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID) override;
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo) override;
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp) override;
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr, 
                                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, 
                                    PWSTR* ppszOptionalStatusText, 
                                    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus, 
                                NTSTATUS ntsSubstatus, 
                                PWSTR* ppszOptionalStatusText, 
                                CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;

    // ICredentialProviderCredential2
    IFACEMETHODIMP GetUserSid(PWSTR* ppszSid) override;

    // ICredentialProviderCredentialWithFieldOptions
    IFACEMETHODIMP GetFieldOptions(DWORD dwFieldID, CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS* pOptions) override;

    // Static Field Descriptors Table
    static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_FieldDescriptors[FIELD_COUNT];

private:
    void UpdateMfaFieldVisibility();
    void SetStatus(const std::wstring& message);

    LONG m_cRef;
    ICredentialProviderCredentialEvents* m_pEvents;

    // User input data
    std::wstring m_username;
    std::wstring m_password;
    std::wstring m_mfaPayload;
    std::wstring m_statusText;
    DWORD m_selectedMfaMethodIndex;

    // Available MFA methods in the dropdown
    std::vector<std::pair<std::wstring, MfaMethod>> m_mfaMethods;

    // Embedded IPC Client from Step 1
    MfaIpcClient m_ipcClient;

    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus;

public:
    void SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus) { m_cpus = cpus; }
};

