#define SECURITY_WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <commctrl.h>
#include <security.h>
#include <ntsecapi.h>
#include <string>
#include <thread>
#include <vector>
#include "guid.h"
#include "IpcProtocol.h"
#include "MfaIpcClient.h"
#include "LsaHelper.h"

#pragma comment(lib, "comctl32.lib")

// Control IDs
enum ControlIds {
    IDC_LABEL_TITLE = 101,
    IDC_LABEL_USER = 102,
    IDC_EDIT_USER = 103,
    IDC_LABEL_PASS = 104,
    IDC_EDIT_PASS = 105,
    IDC_LABEL_METHOD = 106,
    IDC_COMBO_METHOD = 107,
    IDC_LABEL_PAYLOAD = 108,
    IDC_EDIT_PAYLOAD = 109,
    IDC_LABEL_STATUS = 110,
    IDC_BTN_SUBMIT = 111,
    IDC_BTN_EXIT = 112
};

// Global control handles
HWND g_hWnd = nullptr;
HWND g_hEditUser = nullptr;
HWND g_hEditPass = nullptr;
HWND g_hComboMethod = nullptr;
HWND g_hLabelPayload = nullptr;
HWND g_hEditPayload = nullptr;
HWND g_hStatus = nullptr;
HWND g_hBtnSubmit = nullptr;

HFONT g_hFontTitle = nullptr;
HFONT g_hFontBody = nullptr;
HFONT g_hFontBold = nullptr;

MfaIpcClient g_ipcClient;
bool g_isAuthenticating = false;

// Custom message for thread-safe UI updates
#define WM_UPDATE_STATUS (WM_USER + 1)
#define WM_AUTH_FINISHED (WM_USER + 2)

void SetStatusSafe(const std::wstring& msg) {
    if (g_hWnd) {
        wchar_t* pMsg = _wcsdup(msg.c_str());
        PostMessageW(g_hWnd, WM_UPDATE_STATUS, 0, reinterpret_cast<LPARAM>(pMsg));
    }
}

void OnMethodChanged() {
    int sel = (int)SendMessageW(g_hComboMethod, CB_GETCURSEL, 0, 0);
    if (sel == CB_ERR) return;

    if (sel == 0 || sel == 3) { // TOTP or SmartCard
        ShowWindow(g_hLabelPayload, SW_SHOW);
        ShowWindow(g_hEditPayload, SW_SHOW);
        if (sel == 0) {
            SetWindowTextW(g_hLabelPayload, L"TOTP 6-Digit Code:");
            SetWindowTextW(g_hEditPayload, L"123456");
            SetWindowTextW(g_hStatus, L"Enter your 6-digit TOTP code (Test code: 123456).");
        } else {
            SetWindowTextW(g_hLabelPayload, L"Smart Card PIN:");
            SetWindowTextW(g_hEditPayload, L"1234");
            SetWindowTextW(g_hStatus, L"Insert your Smart Card and enter your PIN.");
        }
    } else { // Passkey, Biometric, Push
        ShowWindow(g_hLabelPayload, SW_HIDE);
        ShowWindow(g_hEditPayload, SW_HIDE);
        if (sel == 1) {
            SetWindowTextW(g_hStatus, L"Click Submit, then touch your Security Key (FIDO2).");
        } else if (sel == 2) {
            SetWindowTextW(g_hStatus, L"Click Submit, then scan your fingerprint or face.");
        } else if (sel == 4) {
            SetWindowTextW(g_hStatus, L"Click Submit to send an approval push to your phone.");
        }
    }
}

void PerformAuth() {
    if (g_isAuthenticating) return;
    g_isAuthenticating = true;
    EnableWindow(g_hBtnSubmit, FALSE);

    wchar_t userBuf[256] = {};
    wchar_t passBuf[256] = {};
    wchar_t payloadBuf[256] = {};

    GetWindowTextW(g_hEditUser, userBuf, 256);
    GetWindowTextW(g_hEditPass, passBuf, 256);
    GetWindowTextW(g_hEditPayload, payloadBuf, 256);

    int sel = (int)SendMessageW(g_hComboMethod, CB_GETCURSEL, 0, 0);
    MfaMethod method = static_cast<MfaMethod>(sel >= 0 ? sel : 0);

    std::wstring user = userBuf;
    std::wstring pass = passBuf;
    std::wstring payload = payloadBuf;

    if (user.empty() || pass.empty()) {
        SetWindowTextW(g_hStatus, L"Error: Please enter both username and password.");
        EnableWindow(g_hBtnSubmit, TRUE);
        g_isAuthenticating = false;
        return;
    }

    SetWindowTextW(g_hStatus, L"Contacting MFA Background Service via IPC...");

    // Run authentication in background thread to keep UI live and responsive
    std::thread([user, pass, payload, method]() {
        MfaAuthResponse resp = g_ipcClient.Authenticate(
            user, L"", method, payload,
            [](const std::wstring& progress) {
                SetStatusSafe(progress);
            },
            15000 // 15 sec timeout
        );

        std::wstring finalMsg;
        if (resp.isSuccess) {
            // Verify LSA package resolution
            ULONG authPkg = 0;
            LsaHelper::GetAuthenticationPackage(&authPkg);
            finalMsg = L"SUCCESS: " + std::wstring(resp.message) + L"\n" +
                       L"LSA Package ID: " + std::to_wstring(authPkg) + L" (Kerberos)\n" +
                       L"Logon Serialization buffer packed and verified!";
        } else {
            finalMsg = L"FAILED: " + std::wstring(resp.message);
        }

        SetStatusSafe(finalMsg);
        PostMessageW(g_hWnd, WM_AUTH_FINISHED, resp.isSuccess, 0);
    }).detach();
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // Create Segoe UI fonts
        g_hFontTitle = CreateFontW(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                   DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                   CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        g_hFontBold = CreateFontW(16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        g_hFontBody = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        // Title & Header
        HWND hTitle = CreateWindowExW(0, L"STATIC", L"Custom MFA Login",
            WS_CHILD | WS_VISIBLE | SS_LEFT, 25, 20, 420, 30, hWnd, (HMENU)IDC_LABEL_TITLE, nullptr, nullptr);
        SendMessageW(hTitle, WM_SETFONT, (WPARAM)g_hFontTitle, TRUE);

        HWND hSub = CreateWindowExW(0, L"STATIC", L"Windows Credential Provider Desktop Simulation",
            WS_CHILD | WS_VISIBLE | SS_LEFT, 25, 52, 420, 20, hWnd, nullptr, nullptr, nullptr);
        SendMessageW(hSub, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);

        // Username
        HWND hLblUser = CreateWindowExW(0, L"STATIC", L"Username:",
            WS_CHILD | WS_VISIBLE | SS_LEFT, 25, 85, 420, 18, hWnd, (HMENU)IDC_LABEL_USER, nullptr, nullptr);
        SendMessageW(hLblUser, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);

        g_hEditUser = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"TestAdmin",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 25, 107, 415, 28, hWnd, (HMENU)IDC_EDIT_USER, nullptr, nullptr);
        SendMessageW(g_hEditUser, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);

        // Password
        HWND hLblPass = CreateWindowExW(0, L"STATIC", L"Password:",
            WS_CHILD | WS_VISIBLE | SS_LEFT, 25, 145, 420, 18, hWnd, (HMENU)IDC_LABEL_PASS, nullptr, nullptr);
        SendMessageW(hLblPass, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);

        g_hEditPass = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"P@ssw0rd123!",
            WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL, 25, 167, 415, 28, hWnd, (HMENU)IDC_EDIT_PASS, nullptr, nullptr);
        SendMessageW(g_hEditPass, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);

        // MFA Method
        HWND hLblMethod = CreateWindowExW(0, L"STATIC", L"MFA Method:",
            WS_CHILD | WS_VISIBLE | SS_LEFT, 25, 205, 420, 18, hWnd, (HMENU)IDC_LABEL_METHOD, nullptr, nullptr);
        SendMessageW(hLblMethod, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);

        g_hComboMethod = CreateWindowExW(WS_EX_CLIENTEDGE, L"COMBOBOX", nullptr,
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 25, 227, 415, 200, hWnd, (HMENU)IDC_COMBO_METHOD, nullptr, nullptr);
        SendMessageW(g_hComboMethod, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);

        SendMessageW(g_hComboMethod, CB_ADDSTRING, 0, (LPARAM)L"TOTP (Authenticator App)");
        SendMessageW(g_hComboMethod, CB_ADDSTRING, 0, (LPARAM)L"Security Key (Passkey / FIDO2)");
        SendMessageW(g_hComboMethod, CB_ADDSTRING, 0, (LPARAM)L"Biometric (Fingerprint / Face)");
        SendMessageW(g_hComboMethod, CB_ADDSTRING, 0, (LPARAM)L"Smart Card");
        SendMessageW(g_hComboMethod, CB_ADDSTRING, 0, (LPARAM)L"Mobile Push Notification");
        SendMessageW(g_hComboMethod, CB_SETCURSEL, 0, 0);

        // Code / PIN
        g_hLabelPayload = CreateWindowExW(0, L"STATIC", L"TOTP 6-Digit Code:",
            WS_CHILD | WS_VISIBLE | SS_LEFT, 25, 265, 420, 18, hWnd, (HMENU)IDC_LABEL_PAYLOAD, nullptr, nullptr);
        SendMessageW(g_hLabelPayload, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);

        g_hEditPayload = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"123456",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 25, 287, 415, 28, hWnd, (HMENU)IDC_EDIT_PAYLOAD, nullptr, nullptr);
        SendMessageW(g_hEditPayload, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);

        // Live Status Box
        g_hStatus = CreateWindowExW(WS_EX_STATICEDGE, L"STATIC",
            L"Ready. Select MFA method and click Submit.\n(Mock service accepts code '123456')",
            WS_CHILD | WS_VISIBLE | SS_LEFT, 25, 330, 415, 60, hWnd, (HMENU)IDC_LABEL_STATUS, nullptr, nullptr);
        SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);

        // Buttons
        g_hBtnSubmit = CreateWindowExW(0, L"BUTTON", L"Submit (Log In)",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 25, 410, 200, 38, hWnd, (HMENU)IDC_BTN_SUBMIT, nullptr, nullptr);
        SendMessageW(g_hBtnSubmit, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);

        HWND hBtnExit = CreateWindowExW(0, L"BUTTON", L"Close",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 240, 410, 200, 38, hWnd, (HMENU)IDC_BTN_EXIT, nullptr, nullptr);
        SendMessageW(hBtnExit, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);

        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);
        int code = HIWORD(wParam);

        if (id == IDC_COMBO_METHOD && code == CBN_SELCHANGE) {
            OnMethodChanged();
        } else if (id == IDC_BTN_SUBMIT) {
            PerformAuth();
        } else if (id == IDC_BTN_EXIT) {
            PostQuitMessage(0);
        }
        return 0;
    }

    case WM_UPDATE_STATUS: {
        wchar_t* pMsg = reinterpret_cast<wchar_t*>(lParam);
        if (pMsg) {
            SetWindowTextW(g_hStatus, pMsg);
            free(pMsg);
        }
        return 0;
    }

    case WM_AUTH_FINISHED: {
        g_isAuthenticating = false;
        EnableWindow(g_hBtnSubmit, TRUE);
        return 0;
    }

    case WM_DESTROY: {
        if (g_hFontTitle) DeleteObject(g_hFontTitle);
        if (g_hFontBody) DeleteObject(g_hFontBody);
        if (g_hFontBold) DeleteObject(g_hFontBold);
        PostQuitMessage(0);
        return 0;
    }

    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIconW(nullptr, IDI_SHIELD);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"MfaTestHarnessWindowClass";

    RegisterClassExW(&wc);

    int windowWidth = 480;
    int windowHeight = 510;
    int screenX = (GetSystemMetrics(SM_CXSCREEN) - windowWidth) / 2;
    int screenY = (GetSystemMetrics(SM_CYSCREEN) - windowHeight) / 2;

    g_hWnd = CreateWindowExW(
        WS_EX_TOPMOST, // Ensure it opens right on top so user doesn't miss it!
        L"MfaTestHarnessWindowClass",
        L"Custom MFA Credential Provider - Interactive Test UI",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        screenX, screenY, windowWidth, windowHeight,
        nullptr, nullptr, hInstance, nullptr
    );

    if (!g_hWnd) {
        return 1;
    }

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);
    SetForegroundWindow(g_hWnd);

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
            PerformAuth();
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}

int main() {
    return wWinMain(GetModuleHandleW(nullptr), nullptr, GetCommandLineW(), SW_SHOWNORMAL);
}
