#include "ShowError.h"

BOOL ShowError::ShowErrorInfo(const char* error, DWORD errorcode)
{
	char errorInfo[MAX_PATH];
	wsprintf(errorInfo, "%s[%d]", error, errorcode);
	MessageBoxA(nullptr, errorInfo, "TIP", MB_OK);
	return FALSE;
}