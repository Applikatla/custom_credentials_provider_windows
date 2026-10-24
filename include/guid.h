#pragma once

#include <windows.h>
#include <initguid.h>

// Unique CLSID for the Custom MFA Credential Provider:
// {3A4E2F6C-81D5-4F8A-9A8E-2B6C7D8E9F01}
DEFINE_GUID(CLSID_MfaCredentialProvider,
    0x3a4e2f6c, 0x81d5, 0x4f8a, 0x9a, 0x8e, 0x2b, 0x6c, 0x7d, 0x8e, 0x9f, 0x01);

// Standard Field Type GUID for Logon/Password fields
// {4B6B0E09-8A83-47FD-9B1F-EC81EB2B710A}
DEFINE_GUID(CPFG_LOGON_PASSWORD,
    0x4b6b0e09, 0x8a83, 0x47fd, 0x9b, 0x1f, 0xec, 0x81, 0xeb, 0x2b, 0x71, 0x0a);
