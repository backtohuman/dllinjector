#pragma once

#include <Windows.h>

BOOL WINAPI InjectDllW(__in LPCWSTR lpcwszDll, __in DWORD dwProcessId);