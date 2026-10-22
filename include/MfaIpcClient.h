#pragma once

#include "IpcProtocol.h"
#include <functional>
#include <string>

class MfaIpcClient {
public:
  // Callback invoked whenever an intermediate progress update arrives
  // e.g., to update the status text on the Windows logon tile in real time.
  using ProgressCallback =
      std::function<void(const std::wstring &progressText)>;

  MfaIpcClient(const std::wstring &pipeName = MFA_PIPE_NAME);
  ~MfaIpcClient();

  // Check if the MFA background service pipe is available and listening
  bool IsServiceAvailable(DWORD timeoutMs = 1000);

  // Send an authentication request to the service and await the verdict.
  // Handles intermediate PROGRESS packets via the optional callback.
  MfaAuthResponse Authenticate(const std::wstring &username,
                               const std::wstring &domain, MfaMethod method,
                               const std::wstring &payload = L"",
                               ProgressCallback progressCallback = nullptr,
                               DWORD timeoutMs = 30000);

private:
  std::wstring m_pipeName;
};
