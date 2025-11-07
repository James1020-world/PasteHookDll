#pragma once
#include <windows.h>

#ifdef PASTEHOOKDLL_EXPORTS
#define PHD_API __declspec(dllexport)
#else
#define PHD_API __declspec(dllimport)
#endif

extern "C" {
    PHD_API BOOL InstallHooks(HWND controllerWindow);
    PHD_API BOOL UninstallHooks();
    PHD_API LPCWSTR GetLastClipboardOperation();
}
