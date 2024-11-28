#include "ReadOriginData.h"
#include "ShowError.h"

#pragma   comment(linker,"/subsystem:\"windows\"  /entry:\"mainCRTStartup\""   ) 

const char key[] = "GaGa_2024!!!";

#define STATUS_SUCCESS                        (0x00000000L)

typedef NTSTATUS(WINAPI* PFZWUNMAPVIEWOFSECTION)(HANDLE ProcessHandle, PVOID BaseAddress);

BOOL DecryptData(LPVOID DataBufferAddr, DWORD DataSize);
BOOL RepairIAT(PVOID pBaseAddr);
BOOL UnmapFakeProcImage(const PROCESS_INFORMATION* ppi, const LPBYTE pRealFileBuf);
PVOID WriteMemoryToProcess(HANDLE hProcess, PVOID pSrcFile);
PVOID WriteMemoryToProcess(HANDLE hProcess, PVOID pSrcFile);
PVOID GetOriginMemory(PVOID pBaseAddr);

DWORD Min(DWORD x, DWORD y)
{
	return x < y ? x : y;
}

DWORD ReadOriginData::ReadOriginDataTOBuffer()
{
	char filePath[MAX_PATH]{ 0 };
	GetModuleFileNameA(nullptr, filePath, MAX_PATH);

	LPVOID OriginFileBuffer = nullptr;

	HMODULE result = GetModuleHandle(nullptr);
	auto dos_header = (PIMAGE_DOS_HEADER)result;
	auto nt_header = (PIMAGE_NT_HEADERS32)(DWORD)((BYTE*)dos_header + dos_header->e_lfanew);
	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);
	auto end_setcion_header = (PIMAGE_SECTION_HEADER)&section_header[nt_header->FileHeader.NumberOfSections - 1];
		
	if (strcmp(".GaGa!!!", (const char*)end_setcion_header->Name) != 0)
	{
		ShowError::ShowErrorInfo("δ�ӿ�",-1);
		return FALSE;
	}
	
	DWORD Origin_File_Address = end_setcion_header->PointerToRawData;
	DWORD Origin_Section_Address = end_setcion_header->VirtualAddress;
	DWORD Origin_File_Size = end_setcion_header->Misc.VirtualSize;

	// ��ȡԭʼ����
	OriginFileBuffer = VirtualAlloc(nullptr, Origin_File_Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!OriginFileBuffer)
	{
		
		ShowError::ShowErrorInfo("VirtualAlloc() failed!", GetLastError());
		return FALSE;
	}
	// ����Ҫʹ���ڴ��еĵ�ַ����Ϊ��ʹ��`GetModuleHandle`��ȡ������
	memcpy_s(OriginFileBuffer, Origin_File_Size, ((BYTE*)result + Origin_Section_Address), Origin_File_Size);
	
	// ��Դ���ݽ��н���
	DecryptData(OriginFileBuffer, Origin_File_Size);

	// ��ȡԭʼ�������ڴ��е�״̬
	LPVOID OriginMeroyData = GetOriginMemory(OriginFileBuffer);

	RepairIAT(OriginMeroyData);

	// ��������
	STARTUPINFOA si{ 0 };
	PROCESS_INFORMATION pi{ 0 };
	si.cb = sizeof(STARTUPINFOA);
	if (!CreateProcessA(filePath, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
	{

		ShowError::ShowErrorInfo("CreateProcessA() failed!", GetLastError());
		return FALSE;
	}

	// ж�ؽ��̿ռ�
	if (!UnmapFakeProcImage(&pi, (LPBYTE)OriginMeroyData))
	{		
		ShowError::ShowErrorInfo("DelteProcessBuffer() failed!", GetLastError());
		return FALSE;
	}

	// �ڽ��̿ռ��з����ڴ�
	PVOID pDestProcAddr = WriteMemoryToProcess(pi.hProcess, OriginMeroyData);

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)OriginMeroyData;
	PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)(DWORD)((BYTE*)dos + dos->e_lfanew);
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

	CONTEXT cx;
	cx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(pi.hThread, &cx))
	{
		ShowError::ShowErrorInfo("GetThreadContext() failed!", GetLastError());

		return FALSE;
	}
	cx.Eax = nt->OptionalHeader.AddressOfEntryPoint + (DWORD)pDestProcAddr;
	DWORD dwImageBase = (DWORD)pDestProcAddr;
	if (!WriteProcessMemory(pi.hProcess, (PCHAR)cx.Ebx + 8, &dwImageBase, sizeof(dwImageBase), nullptr))
	{
		ShowError::ShowErrorInfo("WriteProcessMemory() failed!", GetLastError());

		return FALSE;
	}
	if (!SetThreadContext(pi.hThread, &cx))
	{
		ShowError::ShowErrorInfo("SetThreadContext() failed!", GetLastError());


		return FALSE;
	}


	if (!ResumeThread(pi.hThread))
	{
		ShowError::ShowErrorInfo("ResumeThread() failed!", GetLastError());

		return FALSE;
	}

	return (DWORD)OriginFileBuffer;
}

BOOL RepairIAT(PVOID pBaseAddr)
{
	auto pDosHead = (PIMAGE_DOS_HEADER)pBaseAddr;
	auto pFileHead = (PIMAGE_FILE_HEADER)((DWORD)pBaseAddr + pDosHead->e_lfanew + 4);
	auto pOptionHead = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHead + IMAGE_SIZEOF_FILE_HEADER);
	auto pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pBaseAddr + pOptionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	PDWORD pINT = nullptr, pIAT = nullptr;
	PCHAR pDllName = nullptr;
	PIMAGE_IMPORT_BY_NAME pFunName = nullptr;
	DWORD dwFuncAddr = 0, dwOrder = 0;
	HMODULE hModule = nullptr;

	if ((DWORD)pImportTable == (DWORD)pBaseAddr)
	{
		MessageBox(nullptr, TEXT("û�е����"), TEXT("���"), MB_OK);
		return FALSE;
	}

	while (pImportTable->OriginalFirstThunk != 0 || pImportTable->FirstThunk != 0)
	{
		pDllName = (PCHAR)pBaseAddr + pImportTable->Name;    //���dll����ַ
		hModule = LoadLibraryA(pDllName);
		if (!hModule)
		{
			ShowError::ShowErrorInfo("LoadLibraryA() failed!", GetLastError());
			return FALSE;
		}

		pINT = (PDWORD)((DWORD)pBaseAddr + pImportTable->OriginalFirstThunk);
		pIAT = (PDWORD)((DWORD)pBaseAddr + pImportTable->FirstThunk);
		while (*pINT)
		{
			dwFuncAddr = 0;
			if (IMAGE_SNAP_BY_ORDINAL32(*pINT)) //the highest bit is 1?
			{
				dwOrder = *pINT & ~IMAGE_ORDINAL_FLAG32;    //clear highest bit
				dwFuncAddr = (DWORD)GetProcAddress(hModule, (LPCSTR)MAKEINTRESOURCE(dwOrder));   //����ŵķ�ʽ��ȡ������ַ
			}
			else
			{
				pFunName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pBaseAddr + *pINT);
				dwFuncAddr = (DWORD)GetProcAddress(hModule, (PCHAR)pFunName->Name);      //�����ֵķ�ʽ��ȡ������ַ
			}
			*pIAT = dwFuncAddr;
			pINT++;
			pIAT++;
		}
		pImportTable++;
	}
}

BOOL DecryptData(LPVOID DataBufferAddr,DWORD DataSize)
{
	if (!DataBufferAddr)
	{
		ShowError::ShowErrorInfo("���ݴ���",-1);
		return FALSE;
	}
	for (size_t i = 0; i < DataSize; i++)
	{
		BYTE* address = (BYTE*)DataBufferAddr;
		address[i] ^= key[i % strlen(key)];

	}
	return TRUE;
}

BOOL UnmapFakeProcImage(const PROCESS_INFORMATION* ppi, const LPBYTE pRealFileBuf) {
	if (!ppi || !pRealFileBuf) {
		ShowError::ShowErrorInfo("��������", ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	// ��֤PEͷ
	auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pRealFileBuf);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		ShowError::ShowErrorInfo("DOSͷ��Ч", ERROR_BAD_FORMAT);
		return FALSE;
	}

	auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pRealFileBuf + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		ShowError::ShowErrorInfo("NTͷ��Ч", ERROR_BAD_FORMAT);
		return FALSE;
	}

	// ��ȡ�߳�������
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(ppi->hThread, &ctx)) {
		ShowError::ShowErrorInfo("��ȡ�߳������Ĵ���", GetLastError());
		return FALSE;
	}

	// ��ȡ���ܽ��̻�ַ
	DWORD fakeProcImageBase = 0;
	const DWORD PEB_IMAGE_BASE_OFFSET = 8; // PEB.ImageBaseAddress offset
	if (!ReadProcessMemory(ppi->hProcess,
		reinterpret_cast<LPCVOID>(ctx.Ebx + PEB_IMAGE_BASE_OFFSET),
		&fakeProcImageBase,
		sizeof(DWORD),
		nullptr)) {
		ShowError::ShowErrorInfo("Failed to read process memory!", GetLastError());
		return FALSE;
	}

	// �Ƚϻ�ַ
	const auto& optionalHeader = pNtHeaders->OptionalHeader;
	if (optionalHeader.ImageBase == fakeProcImageBase) {
		using ZwUnmapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, PVOID);

		// ��ȡZwUnmapViewOfSection������ַ
		auto hNtdll = GetModuleHandleA("ntdll.dll");
		if (!hNtdll) {
			ShowError::ShowErrorInfo("��ȡ 'ntdll' ����", GetLastError());
			return FALSE;
		}

		auto fnZwUnmapViewOfSection = reinterpret_cast<ZwUnmapViewOfSection_t>(
			GetProcAddress(hNtdll, "ZwUnmapViewOfSection"));
		if (!fnZwUnmapViewOfSection) {
			ShowError::ShowErrorInfo("��ȡ ZwUnmapViewOfSection ��ַ����!", GetLastError());
			return FALSE;
		}

		// ж��ӳ��
		NTSTATUS status = fnZwUnmapViewOfSection(ppi->hProcess,
			reinterpret_cast<PVOID>(fakeProcImageBase));
		if (status != STATUS_SUCCESS) {
			ShowError::ShowErrorInfo("ZwUnmapViewOfSection() failed!", status);
			return FALSE;
		}
	}

	return TRUE;
}

PVOID WriteMemoryToProcess(HANDLE hProcess, PVOID pSrcFile) {
	if (!hProcess || !pSrcFile) {
		ShowError::ShowErrorInfo("Invalid parameters!", ERROR_INVALID_PARAMETER);
		return nullptr;
	}

	// ��ȡPEͷ��Ϣ
	auto pDosHead = static_cast<PIMAGE_DOS_HEADER>(pSrcFile);
	if (pDosHead->e_magic != IMAGE_DOS_SIGNATURE) {
		ShowError::ShowErrorInfo("Invalid DOS signature!", ERROR_BAD_FORMAT);
		return nullptr;
	}

	auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)pSrcFile + pDosHead->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		ShowError::ShowErrorInfo("Invalid NT signature!", ERROR_BAD_FORMAT);
		return nullptr;
	}

	auto pOptionHead = &pNtHeaders->OptionalHeader;
	DWORD dwImageBase = pOptionHead->ImageBase;
	PVOID pBaseAddr = nullptr;
	const DWORD MaxAttempts = 5; // ����Դ���
	DWORD attempts = 0;

	// ���Է����ڴ�
	while (!pBaseAddr && attempts < MaxAttempts) 
	{
		pBaseAddr = VirtualAllocEx(hProcess,
			(PVOID)dwImageBase,
			pOptionHead->SizeOfImage,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);
		if (!pBaseAddr) {
			// ����Ƿ�֧���ض�λ
			if (!pOptionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
				ShowError::ShowErrorInfo("����֧���ض�λ!!!", ERROR_NOT_SUPPORTED);
				return nullptr;
			}
			dwImageBase += 0x100000;
			attempts++;
		}
	}

	if (!pBaseAddr) {
		ShowError::ShowErrorInfo("�޷��Խ��̷����ڴ�", ERROR_NOT_ENOUGH_MEMORY);
		return nullptr;
	}

	// �����Ҫ�ض�λ
	if (dwImageBase != pOptionHead->ImageBase) {
		const DWORD dwGap = dwImageBase - pOptionHead->ImageBase;
		auto pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
			(BYTE*)pSrcFile + pOptionHead->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		// �����ض�λ��
		while (pBaseRelocation->VirtualAddress && pBaseRelocation->SizeOfBlock) {
			const DWORD dwNum = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			auto pOffset = reinterpret_cast<PWORD>((BYTE*)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));

			for (DWORD i = 0; i < dwNum; i++) {
				if ((pOffset[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
					auto pTargetAddr = reinterpret_cast<PDWORD>(
						(BYTE*)pSrcFile + pBaseRelocation->VirtualAddress + (pOffset[i] & 0xFFF));
					*pTargetAddr += dwGap;
				}
			}
			pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
				(BYTE*)pBaseRelocation + pBaseRelocation->SizeOfBlock);
		}
	}

	// д������ڴ�
	if (!WriteProcessMemory(hProcess, pBaseAddr, pSrcFile, pOptionHead->SizeOfImage, nullptr)) {
		ShowError::ShowErrorInfo("WriteProcessMemory() failed!", GetLastError());
		VirtualFreeEx(hProcess, pBaseAddr, 0, MEM_RELEASE);
		return nullptr;
	}

	return pBaseAddr;
}

PVOID GetOriginMemory(PVOID pBaseAddr) {
    if (!pBaseAddr) {
        ShowError::ShowErrorInfo("Invalid base address!", ERROR_INVALID_PARAMETER);
        return nullptr;
    }

    // ��֤DOSͷǩ��
    auto pDosHead = static_cast<PIMAGE_DOS_HEADER>(pBaseAddr);
    if (pDosHead->e_magic != IMAGE_DOS_SIGNATURE) {
        ShowError::ShowErrorInfo("Invalid DOS signature!", ERROR_BAD_FORMAT);
        return nullptr;
    }

    // ��ȡ����֤NTͷ
    auto pNtHead = reinterpret_cast<PIMAGE_NT_HEADERS32>((BYTE*)pBaseAddr + pDosHead->e_lfanew);
    if (pNtHead->Signature != IMAGE_NT_SIGNATURE) {
        ShowError::ShowErrorInfo("Invalid NT signature!", ERROR_BAD_FORMAT);
        return nullptr;
    }

    // �����ڴ�
    PVOID pMemoryAddr = VirtualAlloc(nullptr, 
                                   pNtHead->OptionalHeader.SizeOfImage, 
                                   MEM_COMMIT | MEM_RESERVE, 
                                   PAGE_READWRITE);
    if (!pMemoryAddr) {
        ShowError::ShowErrorInfo("Memory allocation failed!", GetLastError());
        return nullptr;
    }

    try {
        // ����PEͷ
        memcpy(pMemoryAddr, pBaseAddr, pNtHead->OptionalHeader.SizeOfHeaders);

        // ���ƽ���
        auto pSectionHead = IMAGE_FIRST_SECTION(pNtHead);
        const DWORD numberOfSections = pNtHead->FileHeader.NumberOfSections;

        for (DWORD i = 0; i < numberOfSections; i++) {
            auto destAddr = static_cast<BYTE*>(pMemoryAddr) + pSectionHead[i].VirtualAddress;
            auto sourceAddr = static_cast<BYTE*>(pBaseAddr) + pSectionHead[i].PointerToRawData;
            auto copySize = min(pSectionHead[i].Misc.VirtualSize, pSectionHead[i].SizeOfRawData);

            if (copySize > 0) {
                memcpy(destAddr, sourceAddr, copySize);
            }
        }

        return pMemoryAddr;
    }
    catch (...) {
        VirtualFree(pMemoryAddr, 0, MEM_RELEASE);
        ShowError::ShowErrorInfo("Memory copy failed!", ERROR_INVALID_DATA);
        return nullptr;
    }
}