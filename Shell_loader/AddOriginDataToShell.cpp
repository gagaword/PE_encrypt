#include "AddOriginDataToShell.h"
#include <fstream>

const char key[] = "GaGa_2024!!!";

DWORD align_value(unsigned int value, unsigned int align) {
	return (value + align - 1) & ~(align - 1);
}

DWORD WriteFileComputer(FILE_INFO* fileBuffer);

DWORD EncryptOrigin(FILE_INFO* OriginAddress);

DWORD AddSectionShell(FILE_INFO *newFileBuffer, FILE_INFO *OriginFile, FILE_INFO *ShellFile);

DWORD Align(DWORD dwSize, DWORD dwAlign)
{
	return dwSize % dwAlign ? dwSize + dwAlign - dwSize % dwAlign : dwSize;
}

BOOL AddOriginDataToShell::addOriginToShell(FILE_INFO *OriginAddress, FILE_INFO* ShellAddress)
{
	if (!OriginAddress || !ShellAddress)
	{
		printf("数据错误\n");
		return FALSE;
	}

	// 获取Shell信息
	PIMAGE_DOS_HEADER shell_dos_header = (PIMAGE_DOS_HEADER)ShellAddress->FileAddress;
	if (!shell_dos_header)
	{
		printf("shell_dos_header failed[%d]", GetLastError());
		return FALSE;
	}
	PIMAGE_NT_HEADERS32 shell_nt_header = (PIMAGE_NT_HEADERS32)(DWORD)((BYTE*)shell_dos_header + shell_dos_header->e_lfanew);
	PIMAGE_SECTION_HEADER shell_section_header = IMAGE_FIRST_SECTION(shell_nt_header);

	// Shell 节表大小
	DWORD SectionSize = shell_nt_header->FileHeader.NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;
	auto one_section_address = (DWORD)((BYTE*)shell_dos_header + shell_section_header->PointerToRawData);
	auto new_section_header = (PIMAGE_SECTION_HEADER)(DWORD)((BYTE*)shell_section_header + SectionSize);
	BOOL section_KeYong_Size = (one_section_address - (DWORD)new_section_header) > (2 * sizeof(IMAGE_SECTION_HEADER)) ? TRUE : FALSE;
	if (section_KeYong_Size == FALSE)
	{
		printf("节与节表之前间隙不够\n");
		return FALSE;
	}
	// 加密源程序
	if (!EncryptOrigin(OriginAddress))
	{
		printf("EncryptOrigin() failed [%d]\n",GetLastError());
		return FALSE;
	}
	
	// 添加数据到Shell
	LPVOID NewFileBuffer = nullptr;
	DWORD size = Align(OriginAddress->FileSize + ShellAddress->FileSize, shell_nt_header->OptionalHeader.FileAlignment);
	NewFileBuffer = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!NewFileBuffer)
	{
		printf("VirtualAlloc() failed [%d]\n", GetLastError());
		return FALSE;
	}

	FILE_INFO newFileInfo{};
	memcpy_s(NewFileBuffer, (OriginAddress->FileSize + ShellAddress->FileSize), ((const char*)ShellAddress->FileAddress), (ShellAddress->FileSize));
	memcpy_s(((BYTE*)NewFileBuffer + ShellAddress->FileSize), (OriginAddress->FileSize), ((const char*)OriginAddress->FileAddress), (OriginAddress->FileSize));
	newFileInfo.FileAddress = (DWORD)NewFileBuffer;
	newFileInfo.FileSize = OriginAddress->FileSize + ShellAddress->FileSize;

	// 添加节表
	AddSectionShell(&newFileInfo, OriginAddress, ShellAddress);

	// 写入磁盘
	WriteFileComputer(&newFileInfo);

	return TRUE;

}

DWORD EncryptOrigin(FILE_INFO* OriginAddress)
{
	if (!OriginAddress->FileAddress)
	{
		
		return FALSE;
	}
	for (size_t i = 0; i < OriginAddress->FileSize; i++)
	{
		BYTE* address = (BYTE*)OriginAddress->FileAddress;
		address[i] ^= key[i%strlen(key)];
	}
	return TRUE;
}

DWORD AddSectionShell(FILE_INFO *newFileBuffer, FILE_INFO *OriginFile, FILE_INFO *ShellFile)
{
	if (!newFileBuffer->FileAddress)
	{
		printf("AddSectionShell() failed [%d]\n", GetLastError());
		return FALSE;
	}

	auto dos_header = (PIMAGE_DOS_HEADER)newFileBuffer->FileAddress;
	auto nt_header = (PIMAGE_NT_HEADERS32)(DWORD)((BYTE*)dos_header + dos_header->e_lfanew);
	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);

	// 倒数第二个节表位置
	auto end_section_header = (PIMAGE_SECTION_HEADER)&section_header[nt_header->FileHeader.NumberOfSections - 1];
	// 最后一个节表位置
	auto new_section_header = (PIMAGE_SECTION_HEADER)&section_header[nt_header->FileHeader.NumberOfSections];

	memcpy_s(new_section_header->Name, IMAGE_SIZEOF_SHORT_NAME, (const char*)".GaGa!!!", IMAGE_SIZEOF_SHORT_NAME);
	new_section_header->VirtualAddress = align_value((end_section_header->VirtualAddress + end_section_header->Misc.VirtualSize), (nt_header->OptionalHeader.SectionAlignment));
	new_section_header->Misc.VirtualSize = OriginFile->FileSize;
	new_section_header->PointerToRawData = (newFileBuffer->FileAddress + ShellFile->FileSize) - (newFileBuffer->FileAddress);
	new_section_header->SizeOfRawData = OriginFile->FileSize;
	new_section_header->Characteristics |= IMAGE_SCN_MEM_READ;
	
	nt_header->FileHeader.NumberOfSections += 1;
	nt_header->OptionalHeader.SizeOfImage = align_value(new_section_header->VirtualAddress + new_section_header->Misc.VirtualSize, nt_header->OptionalHeader.SectionAlignment);
	return TRUE;
}

DWORD WriteFileComputer(FILE_INFO* fileBuffer)
{
	if (!fileBuffer->FileAddress)
	{
		printf("WriteFileComputer() failed [%d]\n", GetLastError());
		return FALSE;
	}
	std::ofstream file("output.exe", std::ios::binary);
	if (!file) {
		std::cerr << "Failed to open file" << std::endl;
		return 1;
	}
	if (!file) {
		perror("Failed to open file");
		return 1;
	}
	file.write(reinterpret_cast<const char*>(fileBuffer->FileAddress), fileBuffer->FileSize);
	if (!file) {
		std::cerr << "Failed to write data" << std::endl;
	}
	MessageBoxA(nullptr, "加壳成功", "TIP" , MB_OK);
}