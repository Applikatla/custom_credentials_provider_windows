#include "MfaIpcClient.h"
#include <iostream>

// Standalone console runner to test the IPC Client against MockMfaService

int main() {
  std::wcout << L"====================================================\n";
  std::wcout << L"   Testing Custom MFA IPC Client                    \n";
  std::wcout << L"====================================================\n";

  MfaIpcClient client;

  std::wcout << L"[*] Checking if MFA Service is running...\n";
  if (!client.IsServiceAvailable(2000)) {
    std::wcout << L"[-] Service is not reachable on pipe: " << MFA_PIPE_NAME
               << L"\n";
    std::wcout << L"    Please start MockMfaService.exe first.\n";
    return 1;
  }
  std::wcout << L"[+] MFA Service is available!\n\n";

  // Test 1: Send TOTP with code 123456
  std::wcout << L"[*] Sending TOTP Auth Request (Code: 123456)...\n";
  MfaAuthResponse resp =
      client.Authenticate(L"JohnDoe", L"CORP", MfaMethod::Totp, L"123456",
                          [](const std::wstring &progress) {
                            std::wcout << L"    [Progress Update] " << progress
                                       << L"\n";
                          });

  std::wcout << L"[Result] Success: " << (resp.isSuccess ? L"YES" : L"NO")
             << L"\n";
  std::wcout << L"[Result] Message: " << resp.message << L"\n\n";

  // Test 2: Send TOTP with invalid code
  std::wcout
      << L"[*] Sending TOTP Auth Request with wrong code (Code: 999999)...\n";
  resp = client.Authenticate(L"JohnDoe", L"CORP", MfaMethod::Totp, L"999999",
                             [](const std::wstring &progress) {
                               std::wcout << L"    [Progress Update] "
                                          << progress << L"\n";
                             });

  std::wcout << L"[Result] Success: " << (resp.isSuccess ? L"YES" : L"NO")
             << L"\n";
  std::wcout << L"[Result] Message: " << resp.message << L"\n";

  return 0;
}
