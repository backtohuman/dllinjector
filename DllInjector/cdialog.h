#pragma once

#include <Windows.h>
#include <Uxtheme.h>

class CDialog
{
private:
	HWND m_hWnd;
	HIMAGELIST hImageList;
	HWND m_hList, m_hEdit;
	DWORD m_dwTargetPID;

public:
	explicit CDialog(__in HWND hWnd);
	~CDialog();

public:
	BOOL OnCreate(__in HINSTANCE hInstance);
	VOID OnDestroy();

	VOID OnRefresh();
	VOID OnInject();
	VOID OnListNotify(__in LPNMHDR lpnmhdr);

public:
	static INT_PTR CALLBACK DialogProc(__in HWND hWnd, __in UINT uMessage, __in WPARAM wParam, __in LPARAM lParam);
};