#include "ReadFileMeory.h"
DWORD ReadFileMeory::ReadOriginFileMoery(const char *filePath, FILE_INFO *filesize)
{
	if (!filePath)
	{
		printf("ReadOriginFileMoery() failed [%d]\n", GetLastError());

		return FALSE;
	}
	LPVOID FileBuffer = nullptr;
	HANDLE create_file = ::CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!create_file)
	{
		printf("CreateFileA() failed [%d]\n", GetLastError());
		
		return FALSE;
	}

	DWORD FileSize = GetFileSize(create_file, nullptr);
	FileBuffer = VirtualAlloc(nullptr, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!ReadFile(create_file, FileBuffer, FileSize, nullptr, nullptr))
	{
		printf("VirtualAlloc() failed [%d]\n", GetLastError());

		return FALSE;
	}
	
	filesize->FileAddress = (DWORD)FileBuffer;
	filesize->FileSize = FileSize;

	return TRUE;
}