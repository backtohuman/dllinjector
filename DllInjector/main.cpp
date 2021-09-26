#include "stdafx.h"

#include "cdialog.h"
#include "resource.h"

int _tmain(int argc, _TCHAR* argv[])
{
	DialogBoxParam(NULL, MAKEINTRESOURCE(IDD_DIALOG1), NULL, CDialog::DialogProc, (LPARAM)NULL);

	getchar();

	return 0;
}
