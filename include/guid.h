#pragma once

#include <windows.h>
#include <initguid.h>

// Unique CLSID for the Custom MFA Credential Provider:
// {3A4E2F6C-81D5-4F8A-9A8E-2B6C7D8E9F01}
DEFINE_GUID(CLSID_MfaCredentialProvider,
    0x3a4e2f6c, 0x81d5, 0x4f8a, 0x9a, 0x8e, 0x2b, 0x6c, 0x7d, 0x8e, 0x9f, 0x01);
