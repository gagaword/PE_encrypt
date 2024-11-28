#include <windows.h>
#include <iostream>

#pragma once

typedef struct _FILE_INFO
{
	DWORD FileSize;
	DWORD FileAddress;
}FILE_INFO,*PFILE_INFO;

class ReadFileMeory
{
public:
	static DWORD ReadOriginFileMoery(const char* filePath, FILE_INFO *filesize);
};

