#include "stdafx.h"

#include "injector.h"

#include <tlhelp32.h>

BOOL WINAPI ReadProcessMemoryEx(_In_ HANDLE hProcess,
	_In_ LPCVOID lpBaseAddress,
	_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T * lpNumberOfBytesRead)
{
	MEMORY_BASIC_INFORMATION mbi;
	DWORD flOldProtect;

	if (VirtualQueryEx(hProcess, lpBaseAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
	{
		_tprintf(TEXT("VirtualQueryEx errorcode = %d\n"), GetLastError());
		return FALSE;
	}

	if (!mbi.Protect || (mbi.Protect & PAGE_GUARD))
		return FALSE;

	if (!(mbi.Protect & PAGE_READONLY))
	{
		if (!VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, PAGE_READONLY, &flOldProtect))
			return FALSE;

		ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

		return VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, flOldProtect, &flOldProtect);
	}

	return ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

BOOL WINAPI InjectDllW(__in LPCWSTR lpcwszDll, __in DWORD dwProcessId)
{
	INT nLength;
	DWORD dwTemp;
	HANDLE hProcess, hModuleSnap;
	LPVOID lpLoadLibraryW = NULL;
	LPVOID lpRemoteString;
	MODULEENTRY32 me32 = {0};
	BOOL Wow64Process;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == INVALID_HANDLE_VALUE)
		return FALSE;

	if (!IsWow64Process(hProcess, &Wow64Process))
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	if (Wow64Process)
	{
		// process is x86 application running on x64 windows
		hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcessId);
		if (hModuleSnap == INVALID_HANDLE_VALUE)
		{
			_tprintf(TEXT("CreateToolhelp32Snapshot errorcode = %d\n"), GetLastError());

			// close process handle
			CloseHandle(hProcess);

			return FALSE;
		}

		// Set the size of the structure before using it.
		me32.dwSize = sizeof(MODULEENTRY32);

		// Retrieve information about the first module,
		// and exit if unsuccessful
		if (!Module32First(hModuleSnap, &me32))
		{
			_tprintf(TEXT("Module32First errorcode = %d\n"), GetLastError());
			// clean the snapshot object
			CloseHandle(hModuleSnap);

			// close process handle
			CloseHandle(hProcess);

			return FALSE;
		}

		// Now walk the module list of the process,
		do
		{
			if (_tcscmp(me32.szModule, L"KERNEL32.DLL") == 0)
			{
				IMAGE_NT_HEADERS32 nt;
				IMAGE_DOS_HEADER dos;
				IMAGE_EXPORT_DIRECTORY exports;

				// DOS HEADER
				if (!ReadProcessMemoryEx(hProcess, me32.hModule, &dos, sizeof(dos), NULL))
					break;

				// NT HEADER
				if (!ReadProcessMemoryEx(hProcess, reinterpret_cast<PBYTE>(me32.hModule) + dos.e_lfanew, &nt, sizeof(nt), NULL))
					break;

				// EXPORT TABLE
				if (!ReadProcessMemoryEx(hProcess, reinterpret_cast<PBYTE>(me32.hModule) + nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, &exports, sizeof(exports), NULL))
					break;

				if (exports.NumberOfFunctions <= 0)
					break;

				DWORD* lpAddressOfNames = new DWORD[exports.NumberOfNames];
				CHAR szTemp[256];

				if (!ReadProcessMemoryEx(hProcess, reinterpret_cast<PBYTE>(me32.hModule) + exports.AddressOfNames, lpAddressOfNames, sizeof(DWORD) * exports.NumberOfNames, NULL))
					break;

				for (UINT uIndex = 0; uIndex < exports.NumberOfNames; uIndex++)
				{
					if (!ReadProcessMemoryEx(hProcess, reinterpret_cast<PBYTE>(me32.hModule) + lpAddressOfNames[uIndex], &szTemp, _countof(szTemp), NULL))
						break;

					if (strcmp(szTemp, "LoadLibraryW") == 0)
					{
						if (!ReadProcessMemoryEx(hProcess, reinterpret_cast<PBYTE>(me32.hModule) + exports.AddressOfFunctions + (uIndex * sizeof(DWORD)), &dwTemp, sizeof(dwTemp), NULL))
							break;

						lpLoadLibraryW = reinterpret_cast<PBYTE>(me32.hModule) + dwTemp;
					}
				}

				delete[] lpAddressOfNames;

				break;
			}
		} while (Module32Next(hModuleSnap, &me32));

		// clean the snapshot object
		CloseHandle(hModuleSnap);
	}
	else
		lpLoadLibraryW = GetProcAddress(GetModuleHandle(L"KERNEL32.DLL"), "LoadLibraryW");

	if (lpLoadLibraryW)
	{
		nLength = wcslen(lpcwszDll) * sizeof(WCHAR);

		// allocate mem for dll name
		lpRemoteString = VirtualAllocEx(hProcess, NULL, nLength + 1, MEM_COMMIT, PAGE_READWRITE);
		if (!lpRemoteString)
		{
			_tprintf(TEXT("VirtualAllocEx errorcode = %d\n"), GetLastError());
			// clean the snapshot object
			CloseHandle(hModuleSnap);

			// close process handle
			CloseHandle(hProcess);

			return FALSE;
		}

		// write dll name
		WriteProcessMemory(hProcess, lpRemoteString, lpcwszDll, nLength, NULL);

		// call loadlibraryw
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)lpLoadLibraryW, lpRemoteString, NULL, NULL);

		WaitForSingleObject(hThread, 4000);

		// free mem
		VirtualFreeEx(hProcess, lpRemoteString, 0, MEM_RELEASE);

		return TRUE;
	}

	// close process handle
	CloseHandle(hProcess);

	return FALSE;
}