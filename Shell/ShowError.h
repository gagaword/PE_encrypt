#pragma once
#include <windows.h>
#include <iostream>

class ShowError
{
public:
	static BOOL ShowErrorInfo(const char* error, DWORD errorcode);
};
 
