#include "MfaIpcClient.h"
#include <cwchar>

MfaIpcClient::MfaIpcClient(const std::wstring &pipeName)
    : m_pipeName(pipeName) {}

MfaIpcClient::~MfaIpcClient() {}

bool MfaIpcClient::IsServiceAvailable(DWORD timeoutMs) {
  return WaitNamedPipeW(m_pipeName.c_str(), timeoutMs) != FALSE;
}

MfaAuthResponse MfaIpcClient::Authenticate(const std::wstring &username,
                                           const std::wstring &domain,
                                           MfaMethod method,
                                           const std::wstring &payload,
                                           ProgressCallback progressCallback,
                                           DWORD timeoutMs) {
  MfaAuthResponse finalResponse = {};
  finalResponse.magic = MFA_IPC_MAGIC;
  finalResponse.version = MFA_IPC_VERSION;
  finalResponse.responseType = MfaResponseType::FinalResult;
  finalResponse.isSuccess = 0;
  finalResponse.errorCode = -1;

  // 1. Wait for the pipe to become available
  if (!WaitNamedPipeW(m_pipeName.c_str(), timeoutMs)) {
    DWORD err = GetLastError();
    finalResponse.errorCode = static_cast<int32_t>(err);
    if (err == ERROR_FILE_NOT_FOUND) {
      wcscpy_s(finalResponse.message, L"MFA Service is not running.");
    } else {
      wcscpy_s(finalResponse.message, L"MFA Service connection timed out.");
    }
    return finalResponse;
  }

  // 2. Open connection to the Named Pipe
  HANDLE hPipe = CreateFileW(m_pipeName.c_str(), GENERIC_READ | GENERIC_WRITE,
                             0,       // No sharing
                             nullptr, // Default security attributes
                             OPEN_EXISTING,
                             0, // Synchronous I/O
                             nullptr);

  if (hPipe == INVALID_HANDLE_VALUE) {
    finalResponse.errorCode = static_cast<int32_t>(GetLastError());
    wcscpy_s(finalResponse.message, L"Failed to connect to MFA Service.");
    return finalResponse;
  }

  // 3. Set pipe to message-read mode so ReadFile respects message boundaries
  DWORD dwMode = PIPE_READMODE_MESSAGE;
  if (!SetNamedPipeHandleState(hPipe, &dwMode, nullptr, nullptr)) {
    CloseHandle(hPipe);
    finalResponse.errorCode = static_cast<int32_t>(GetLastError());
    wcscpy_s(finalResponse.message, L"Failed to configure pipe mode.");
    return finalResponse;
  }

  // 4. Build the request structure
  MfaAuthRequest request = {};
  request.magic = MFA_IPC_MAGIC;
  request.version = MFA_IPC_VERSION;
  request.method = method;
  wcsncpy_s(request.username, username.c_str(), _TRUNCATE);
  wcsncpy_s(request.domain, domain.c_str(), _TRUNCATE);
  wcsncpy_s(request.payload, payload.c_str(), _TRUNCATE);

  // 5. Send the request
  DWORD bytesWritten = 0;
  BOOL writeSuccess = WriteFile(hPipe, &request, sizeof(MfaAuthRequest),
                                &bytesWritten, nullptr);

  if (!writeSuccess || bytesWritten != sizeof(MfaAuthRequest)) {
    CloseHandle(hPipe);
    finalResponse.errorCode = static_cast<int32_t>(GetLastError());
    wcscpy_s(finalResponse.message, L"Failed to send authentication request.");
    return finalResponse;
  }

  // 6. Loop reading responses until the FinalResult verdict arrives
  while (true) {
    MfaAuthResponse incoming = {};
    DWORD bytesRead = 0;

    BOOL readSuccess = ReadFile(hPipe, &incoming, sizeof(MfaAuthResponse),
                                &bytesRead, nullptr);

    if (!readSuccess || bytesRead != sizeof(MfaAuthResponse)) {
      finalResponse.errorCode = static_cast<int32_t>(GetLastError());
      wcscpy_s(finalResponse.message, L"Connection lost with MFA Service.");
      break;
    }

    // Validate packet integrity
    if (incoming.magic != MFA_IPC_MAGIC ||
        incoming.version != MFA_IPC_VERSION) {
      finalResponse.errorCode = -2;
      wcscpy_s(finalResponse.message, L"Invalid response from MFA Service.");
      break;
    }

    // Handle intermediate progress update (e.g. "Touch security key...")
    if (incoming.responseType == MfaResponseType::Progress) {
      if (progressCallback) {
        progressCallback(incoming.message);
      }
      continue; // Keep waiting for the final result
    }

    // Final verdict received
    if (incoming.responseType == MfaResponseType::FinalResult) {
      finalResponse = incoming;
      break;
    }
  }

  CloseHandle(hPipe);
  return finalResponse;
}
