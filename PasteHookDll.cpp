#define PASTEHOOKDLL_EXPORTS
#include "PasteHookDll.h"
#include <windows.h>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>
#include <winreg.h>

HHOOK g_hKeyboardHook = NULL;
HHOOK g_hGetMsgHook = NULL;
HHOOK g_hCallWndHook = NULL;
HWND  g_controllerWnd = NULL;
HINSTANCE g_hInst = NULL;

const UINT WM_PASTE_BLOCKED = WM_USER + 0x200;
const UINT WM_COPY_DETECTED = WM_USER + 0x201; // Ctrl+C
const UINT WM_CUT_DETECTED = WM_USER + 0x202;  // Ctrl+X

const int ID_EDIT_PASTE = 0x302;

static std::wstring g_lastClipboardOperation = L"None";
static std::mutex g_operationMutex; 

// ---- Logging ----
std::mutex g_logMutex;

std::wstring GuidToString(REFGUID guid) {
    WCHAR guidStr[39];
    StringFromGUID2(guid, guidStr, 39);
    return std::wstring(guidStr);
}

static bool IsPasteKey(const KBDLLHOOKSTRUCT* p) {
    if (!p) return false;
    if ((p->vkCode == 'V' || p->vkCode == VK_INSERT) && !(p->flags & LLKHF_UP)) {
        SHORT ctrl = GetKeyState(VK_CONTROL);
        SHORT shift = GetKeyState(VK_SHIFT);
        if (p->vkCode == 'V' && (ctrl & 0x8000)) return true;
        if (p->vkCode == VK_INSERT && (shift & 0x8000)) return true;
    }
    return false;
}

static bool IsCopyKey(const KBDLLHOOKSTRUCT* p) {
    if (!p) return false;
    if (p->vkCode == 'C' && !(p->flags & LLKHF_UP)) {
        SHORT ctrl = GetKeyState(VK_CONTROL);
        return (ctrl & 0x8000);
    }
    return false;
}

static bool IsCutKey(const KBDLLHOOKSTRUCT* p) {
    if (!p) return false;
    if (p->vkCode == 'X' && !(p->flags & LLKHF_UP)) {
        SHORT ctrl = GetKeyState(VK_CONTROL);
        return (ctrl & 0x8000);
    }
    return false;
}

std::wstring GetDllDirectory() {
    WCHAR dllPath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(GetModuleHandleW(L"PasteHookDll.dll"), dllPath, MAX_PATH)) {
#ifdef PathRemoveFileSpecW
        PathRemoveFileSpecW(dllPath);
#else
        std::wstring path(dllPath);
        size_t pos = path.find_last_of(L"\\");
        if (pos != std::wstring::npos) {
            path.resize(pos);
        }
        wcscpy_s(dllPath, MAX_PATH, path.c_str());
#endif
        return std::wstring(dllPath) + L"\\";
    }
    return L"";
}

std::wstring readAppDirFromRegistry() {
    HKEY hKey;
    LONG res = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\BlazeCopy", 0, KEY_READ, &hKey);
    if (res != ERROR_SUCCESS) {
        return L"";  // Empty on failure
    }

    DWORD type = 0;
    DWORD dataSize = 0;
    res = RegQueryValueExW(hKey, L"AppDir", NULL, &type, NULL, &dataSize);
    if (res != ERROR_SUCCESS || type != REG_SZ || dataSize == 0) {
        RegCloseKey(hKey);
        return L"";
    }

    // Allocate buffer for the value (including null terminator)
    std::vector<wchar_t> buffer(dataSize / sizeof(wchar_t));
    res = RegQueryValueExW(hKey, L"AppDir", NULL, NULL, (BYTE*)buffer.data(), &dataSize);
    RegCloseKey(hKey);

    if (res == ERROR_SUCCESS) {
        // Convert to std::wstring (exclude null terminator for size)
        return std::wstring(buffer.data(), (dataSize / sizeof(wchar_t)) - 1);
    }

    return L"";
}

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        auto* p = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);

        // Read app dir from registry and build config path
        std::wstring appDir = readAppDirFromRegistry();
        std::wstring configPath;
        if (!appDir.empty()) {
            configPath = appDir + L"\\Config.ini";
        }
        else {
            // Fallback: disable keyboard shortcut or log error
            // For now, we'll assume unsupported if config can't be read
            OutputDebugStringW(L"[DLL] Failed to read app dir from registry - keyboard shortcuts disabled\n");
            return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
        }

        BOOL keyboardShortcutSupported = GetPrivateProfileIntW(L"ShellCopy", L"KeyboardShortcutSupported", 0, configPath.c_str());

        if (!keyboardShortcutSupported) {
            return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
        }

        if (p->flags & LLKHF_INJECTED) {
            return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
        }

        if (IsPasteKey(p)) {

            if (g_controllerWnd && IsWindow(g_controllerWnd)) {
                PostMessage(g_controllerWnd, WM_PASTE_BLOCKED, 0, 0);
            }
            return 1;
            // return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
        }
        else if (IsCopyKey(p)) {
            std::lock_guard<std::mutex> lock(g_operationMutex);
            g_lastClipboardOperation = L"Copy";
            if (g_controllerWnd && IsWindow(g_controllerWnd)) {
                PostMessage(g_controllerWnd, WM_COPY_DETECTED, 0, 0);
            }
            return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam); // Allow default copy
        }
        else if (IsCutKey(p)) {
            std::lock_guard<std::mutex> lock(g_operationMutex);
            g_lastClipboardOperation = L"Cut";
            if (g_controllerWnd && IsWindow(g_controllerWnd)) {
                PostMessage(g_controllerWnd, WM_CUT_DETECTED, 0, 0);
            }
            return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam); // Allow default cut
        }
    }
    return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
}

LRESULT CALLBACK GetMsgProc(int code, WPARAM wParam, LPARAM lParam) {
    if (code >= 0 && lParam) {
        MSG* msg = reinterpret_cast<MSG*>(lParam);
        if (msg) {
            if (msg->message == WM_PASTE ||
                msg->message == WM_DROPFILES ||
                (msg->message == WM_COMMAND && LOWORD(msg->wParam) == ID_EDIT_PASTE))
            {
                if (g_controllerWnd && IsWindow(g_controllerWnd)) {
                    PostMessage(g_controllerWnd, WM_PASTE_BLOCKED, (WPARAM)msg->hwnd, (LPARAM)msg->message);
                }

                msg->message = WM_NULL;
                msg->wParam = 0;
                msg->lParam = 0;
                return 1;
            }
        }
    }
    return CallNextHookEx(g_hGetMsgHook, code, wParam, lParam);
}

LRESULT CALLBACK CallWndProcHook(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && lParam) {
        CWPSTRUCT* p = reinterpret_cast<CWPSTRUCT*>(lParam);
        if (p) {
            if (p->message == WM_PASTE ||
                p->message == WM_DROPFILES ||
                (p->message == WM_COMMAND && LOWORD(p->wParam) == ID_EDIT_PASTE))
            {
                if (g_controllerWnd && IsWindow(g_controllerWnd)) {
                    PostMessage(g_controllerWnd, WM_PASTE_BLOCKED, (WPARAM)p->hwnd, (LPARAM)p->message);
                }

                p->message = WM_NULL;
                p->wParam = 0;
                p->lParam = 0;
            }
        }
    }
    return CallNextHookEx(g_hCallWndHook, nCode, wParam, lParam);
}

PHD_API LPCWSTR GetLastClipboardOperation() {
    std::lock_guard<std::mutex> lock(g_operationMutex);
    return g_lastClipboardOperation.c_str();
}

PHD_API BOOL InstallHooks(HWND controllerWindow) {
    if (!controllerWindow || !IsWindow(controllerWindow)) {
        return FALSE;
    }
    g_controllerWnd = controllerWindow;

    if (g_hKeyboardHook || g_hGetMsgHook || g_hCallWndHook) {
        return FALSE;
    }

    g_hKeyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, g_hInst, 0);
    g_hGetMsgHook = SetWindowsHookExW(WH_GETMESSAGE, GetMsgProc, g_hInst, 0);
    g_hCallWndHook = SetWindowsHookExW(WH_CALLWNDPROC, CallWndProcHook, g_hInst, 0);

    if (!g_hKeyboardHook && !g_hGetMsgHook && !g_hCallWndHook) return FALSE;

    return TRUE;
}

PHD_API BOOL UninstallHooks() {
    BOOL ok = TRUE;
    if (g_hKeyboardHook) { ok &= UnhookWindowsHookEx(g_hKeyboardHook); g_hKeyboardHook = NULL; }
    if (g_hGetMsgHook) { ok &= UnhookWindowsHookEx(g_hGetMsgHook);   g_hGetMsgHook = NULL; }
    if (g_hCallWndHook) { ok &= UnhookWindowsHookEx(g_hCallWndHook);  g_hCallWndHook = NULL; }
    g_controllerWnd = NULL;
    return ok;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        g_hInst = (HINSTANCE)hModule;
        DisableThreadLibraryCalls(hModule);
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        UninstallHooks();
    }
    return TRUE;
}