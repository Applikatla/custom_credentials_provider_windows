#include "IpcProtocol.h"
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

// A mock background MFA service simulating the other developer's service.
// This allows testing the Credential Provider IPC client without needing
// the full production MFA hardware / backend service ready.

void ProcessClient(HANDLE hPipe) {
  MfaAuthRequest request = {};
  DWORD bytesRead = 0;

  BOOL readOk =
      ReadFile(hPipe, &request, sizeof(MfaAuthRequest), &bytesRead, nullptr);
  if (!readOk || bytesRead != sizeof(MfaAuthRequest)) {
    std::wcout << L"[-] Failed to read request from pipe.\n";
    CloseHandle(hPipe);
    return;
  }

  std::wcout << L"\n[+] Incoming Authentication Request:\n";
  std::wcout << L"    User:    " << request.username << L"@" << request.domain
             << L"\n";
  std::wcout << L"    Method:  " << static_cast<uint32_t>(request.method)
             << L"\n";
  std::wcout << L"    Payload: " << request.payload << L"\n";

  // 1. Simulate sending an intermediate PROGRESS update
  std::this_thread::sleep_for(std::chrono::milliseconds(800));
  MfaAuthResponse progress = {};
  progress.magic = MFA_IPC_MAGIC;
  progress.version = MFA_IPC_VERSION;
  progress.responseType = MfaResponseType::Progress;
  progress.isSuccess = 0;
  progress.errorCode = 0;

  switch (request.method) {
  case MfaMethod::Passkey:
    wcscpy_s(progress.message, L"Please touch your security key...");
    break;
  case MfaMethod::Biometric:
    wcscpy_s(progress.message, L"Scanning biometric sensor...");
    break;
  case MfaMethod::Push:
    wcscpy_s(progress.message, L"Push notification sent to mobile device...");
    break;
  case MfaMethod::Totp:
  default:
    wcscpy_s(progress.message, L"Verifying one-time code...");
    break;
  }

  DWORD bytesWritten = 0;
  WriteFile(hPipe, &progress, sizeof(MfaAuthResponse), &bytesWritten, nullptr);
  FlushFileBuffers(hPipe);

  // 2. Simulate processing delay
  std::this_thread::sleep_for(std::chrono::milliseconds(1200));

  // 3. Send final verdict
  MfaAuthResponse finalVerdict = {};
  finalVerdict.magic = MFA_IPC_MAGIC;
  finalVerdict.version = MFA_IPC_VERSION;
  finalVerdict.responseType = MfaResponseType::FinalResult;

  // For testing:
  // If TOTP is used, accept "123456" as correct code, reject others.
  // For other methods, approve automatically.
  if (request.method == MfaMethod::Totp) {
    if (wcscmp(request.payload, L"123456") == 0) {
      finalVerdict.isSuccess = 1;
      finalVerdict.errorCode = 0;
      wcscpy_s(finalVerdict.message, L"MFA Verification Successful!");
    } else {
      finalVerdict.isSuccess = 0;
      finalVerdict.errorCode = 1001;
      wcscpy_s(finalVerdict.message, L"Invalid TOTP code. Please try again.");
    }
  } else {
    finalVerdict.isSuccess = 1;
    finalVerdict.errorCode = 0;
    wcscpy_s(finalVerdict.message, L"MFA Verification Successful!");
  }

  WriteFile(hPipe, &finalVerdict, sizeof(MfaAuthResponse), &bytesWritten,
            nullptr);
  FlushFileBuffers(hPipe);

  DisconnectNamedPipe(hPipe);
  CloseHandle(hPipe);
  std::wcout << L"[+] Response sent: "
             << (finalVerdict.isSuccess ? L"APPROVED" : L"REJECTED") << L"\n";
}

int main() {
  std::wcout << L"====================================================\n";
  std::wcout << L"   Mock Windows MFA Background Service (IPC Server) \n";
  std::wcout << L"   Listening on: " << MFA_PIPE_NAME << L"\n";
  std::wcout << L"====================================================\n";

  while (true) {
    HANDLE hPipe =
        CreateNamedPipeW(MFA_PIPE_NAME, PIPE_ACCESS_DUPLEX,
                         PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                         PIPE_UNLIMITED_INSTANCES, sizeof(MfaAuthResponse),
                         sizeof(MfaAuthRequest), 0, nullptr);

    if (hPipe == INVALID_HANDLE_VALUE) {
      std::wcout << L"[-] Failed to create Named Pipe. Error: "
                 << GetLastError() << L"\n";
      std::this_thread::sleep_for(std::chrono::seconds(2));
      continue;
    }

    std::wcout
        << L"[*] Waiting for connection from Credential Provider DLL...\n";
    BOOL connected = ConnectNamedPipe(hPipe, nullptr)
                         ? TRUE
                         : (GetLastError() == ERROR_PIPE_CONNECTED);

    if (connected) {
      std::wcout << L"[+] Credential Provider connected!\n";
      ProcessClient(hPipe);
    } else {
      CloseHandle(hPipe);
    }
  }

  return 0;
}
