#include "stdafx.h"

#include "cdialog.h"
#include "injector.h"
#include "resource.h"

#include <Psapi.h>
#include <string>
#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>
#include <TlHelp32.h>

#pragma  comment(lib, "comctl32")

CDialog::CDialog(__in HWND hWnd)
{
	m_hWnd = hWnd;

	SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)this);
}

CDialog::~CDialog()
{
	if (hImageList)
		ImageList_Destroy(hImageList);
}

BOOL CDialog::OnCreate(__in HINSTANCE hInstance)
{
	// set window text
	SetWindowText(m_hWnd, L"DLL Injector");

	// list view
	m_hList = GetDlgItem(m_hWnd, IDC_LIST1);
	if (m_hList == NULL)
		return FALSE;

	// edit control
	m_hEdit = GetDlgItem(m_hWnd, IDC_EDIT2);
	if (m_hEdit == NULL)
		return FALSE;

	hImageList = ImageList_Create(16, 16, ILC_COLOR32, 0, 256);

	std::wstring wstrTemp;
	LVCOLUMN lvc;

	wstrTemp = L"PID";
	/***/
	lvc.mask = LVCF_WIDTH | LVCF_TEXT | LVCF_FMT;
	lvc.fmt = LVCFMT_CENTER;
	lvc.cx = 80;
	lvc.pszText = (LPWSTR)wstrTemp.c_str();
	if (ListView_InsertColumn(m_hList, 0, &lvc) == -1)
		return FALSE;

	wstrTemp = L"Process";
	/***/
	lvc.mask = LVCF_WIDTH | LVCF_TEXT | LVCF_FMT;
	lvc.fmt = LVCFMT_CENTER;
	lvc.cx = 80;
	lvc.pszText = (LPWSTR)wstrTemp.c_str();
	if (ListView_InsertColumn(m_hList, 1, &lvc) == -1)
		return FALSE;

	ListView_SetColumnWidth(m_hList, 1, LVSCW_AUTOSIZE_USEHEADER);
	ListView_SetImageList(m_hList, hImageList, LVSIL_SMALL);
	ListView_SetExtendedListViewStyle(m_hList, LVS_EX_SUBITEMIMAGES | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER | LVS_OWNERDATA);

	return TRUE;
}

VOID CDialog::OnDestroy()
{
	delete this;
}

VOID CDialog::OnRefresh()
{
	HANDLE hProcessSnap, hProcess;
	PROCESSENTRY32 pe32;

	SHFILEINFO sfi = { 0 };

	INT				nIndex, nDefault;
	LVITEM			lvi;
	WCHAR			wszTemp[MAX_PATH];
	std::wstring	wstrTemp;

	// clear list view items
	ListView_DeleteAllItems(m_hList);

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return;

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return;
	}

	if (!SUCCEEDED(SHGetFileInfo(L".exe", FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES)))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return;
	}

	nDefault = ImageList_AddIcon(hImageList, sfi.hIcon);
	DestroyIcon(sfi.hIcon);

	do
	{
		lvi.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
		lvi.iImage = nDefault;
		lvi.lParam = (LPARAM)pe32.th32ProcessID;

		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
		if (hProcess != INVALID_HANDLE_VALUE)
		{
			if (GetModuleFileNameEx(hProcess, NULL, wszTemp, MAX_PATH))
			{
				if (SUCCEEDED(SHGetFileInfo(wszTemp, -1, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_LARGEICON)))
				{
					nIndex = ImageList_AddIcon(hImageList, sfi.hIcon);
					if (nIndex != -1)
					{
						lvi.iImage = nIndex;
						DestroyIcon(sfi.hIcon);
					}
				}
			}
		}

		// processid
		lvi.iItem = ListView_GetItemCount(m_hList);
		lvi.iSubItem = 0;

		if (SUCCEEDED(StringCchPrintf(wszTemp, _countof(wszTemp), L"%d", pe32.th32ProcessID)))
			lvi.pszText = wszTemp;

		ListView_InsertItem(m_hList, &lvi);

		// process
		lvi.pszText = wszTemp;
		lvi.mask = LVIF_TEXT;
		lvi.iSubItem = 1;

		if (SUCCEEDED(StringCchPrintf(wszTemp, _countof(wszTemp), L"%s", pe32.szExeFile)))
			lvi.pszText = wszTemp;

		ListView_SetItem(m_hList, &lvi);

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
}

VOID CDialog::OnInject()
{
	OPENFILENAME ofn = { 0 };
	WCHAR wszFile[MAX_PATH];

	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = wszFile;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = L"dll\0*.dll\0";
	ofn.nFilterIndex = 0;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (GetOpenFileName(&ofn))
		if (InjectDllW(ofn.lpstrFile, m_dwTargetPID))
			_tprintf(_TEXT("Success!!\n"));
}

INT CALLBACK lvCompare(LPARAM lParam1, LPARAM lParam2, LPARAM lParam3)
{
	if (lParam1 > lParam2)
		return TRUE;

	return FALSE;
}

VOID CDialog::OnListNotify(__in LPNMHDR lpnmhdr)
{
	switch (lpnmhdr->code)
	{
	case NM_CLICK:
	{
		{
			LVITEM  lvi;
			WCHAR wszTemp[MAX_PATH];
			DWORD dwTemp;

			lvi.iItem = ((LPNMITEMACTIVATE)lpnmhdr)->iItem;
			lvi.mask = LVIF_PARAM;
			lvi.iSubItem = 0;

			if (!ListView_GetItem(m_hList, &lvi))
				return;

			dwTemp = lvi.lParam;

			lvi.iItem = ((LPNMITEMACTIVATE)lpnmhdr)->iItem;
			lvi.mask = LVIF_TEXT;
			lvi.iSubItem = 1;
			lvi.pszText = wszTemp;
			lvi.cchTextMax = MAX_PATH / sizeof(WCHAR);

			if (!ListView_GetItem(m_hList, &lvi))
				return;

			m_dwTargetPID = dwTemp;
			SetWindowText(m_hEdit, wszTemp);
		}
	}
	break;
	case LVN_COLUMNCLICK:
		ListView_SortItems(m_hList, lvCompare, ((NM_LISTVIEW*)lpnmhdr)->iSubItem);
		break;
	}
}

INT_PTR CALLBACK CDialog::DialogProc(__in HWND hWnd, __in UINT uMessage, __in WPARAM wParam, __in LPARAM lParam)
{
	switch (uMessage)
	{
	case WM_INITDIALOG:
		if (!(new CDialog(hWnd))->OnCreate((HINSTANCE)lParam))
			EndDialog(hWnd, EXIT_FAILURE);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON1:
			reinterpret_cast<CDialog*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA))->OnRefresh();
			break;

		case IDC_BUTTON2:
			reinterpret_cast<CDialog*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA))->OnInject();
			break;
		}
		break;

	case WM_NOTIFY:
		if (((LPNMHDR)lParam)->idFrom == IDC_LIST1)
			reinterpret_cast<CDialog*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA))->OnListNotify((LPNMHDR)lParam);
		break;

	case WM_CLOSE:
		EndDialog(hWnd, EXIT_SUCCESS);
		break;

	case WM_DESTROY:
		reinterpret_cast<CDialog*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA))->OnDestroy();
		break;

	default:
		return FALSE;
	}

	return TRUE;
}