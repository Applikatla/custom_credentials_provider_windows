#pragma once

#include <cstdint>
#include <windows.h>

// Default Named Pipe path connecting LogonUI to the MFA Service.
// Windows Named Pipes automatically handle cross-session communication.
#define MFA_PIPE_NAME L"\\\\.\\pipe\\CustomWindowsMfaPipe"

// Protocol Magic & Version
constexpr uint32_t MFA_IPC_MAGIC = 0x4D464131; // "MFA1"
constexpr uint32_t MFA_IPC_VERSION = 1;

// Supported MFA methods selectable in the Credential Provider UI
enum class MfaMethod : uint32_t {
  Totp = 0,      // Standard 6-digit TOTP / OTP
  Passkey = 1,   // FIDO2 / WebAuthn hardware security key
  Biometric = 2, // Fingerprint / Face sensor
  SmartCard = 3, // Smart Card / PKI token
  Push = 4       // Mobile push notification
};

// Response message type
enum class MfaResponseType : uint32_t {
  Progress = 0,   // Intermediate progress update (e.g. "Touch security key...")
  FinalResult = 1 // Final authentication verdict (Success or Failure)
};

#pragma pack(push, 1)

// Request sent from Credential Provider DLL -> MFA Background Service
struct MfaAuthRequest {
  uint32_t magic;        // Must be MFA_IPC_MAGIC
  uint32_t version;      // Protocol version (1)
  MfaMethod method;      // Chosen MFA method
  wchar_t username[256]; // Windows user name
  wchar_t domain[256];   // Windows domain / machine name
  wchar_t payload[256]; // Optional user-typed OTP code, PIN, or extra parameter
};

// Response sent from MFA Background Service -> Credential Provider DLL
struct MfaAuthResponse {
  uint32_t magic;               // Must be MFA_IPC_MAGIC
  uint32_t version;             // Protocol version (1)
  MfaResponseType responseType; // Progress update vs Final verdict
  uint8_t isSuccess;            // 1 = Approved, 0 = Rejected / Failed
  int32_t errorCode;            // 0 = OK, non-zero = specific error code
  wchar_t message[256];         // Text to display on the Windows logon tile
};

#pragma pack(pop)
