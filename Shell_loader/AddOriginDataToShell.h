#pragma once
#include <windows.h>
#include <iostream>
#include "ReadFileMeory.h"

class AddOriginDataToShell
{
public:
	static BOOL addOriginToShell(FILE_INFO* OriginAddress, FILE_INFO* ShellAddress);
};

