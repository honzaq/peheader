// peheader.cpp : Defines the entry point for the console application.
//

#include <windows.h>
#include <tchar.h>
#include <assert.h>

inline void DebugFormat(const TCHAR* szFormat, ...)
{
	TCHAR szBuff[1024];
	memset(szBuff, 0, sizeof(szBuff));

	va_list arg;
	va_start(arg, szFormat);
	_vsntprintf_s(szBuff, sizeof(szBuff) / sizeof(TCHAR), _TRUNCATE, szFormat, arg);
	va_end(arg);

	::OutputDebugString(szBuff);
};

int _tmain(int argc, const _TCHAR* argv[])
{
	if(argc < 1) {
		assert(false && "Missing file path argument");
		return -1;
	}

	//////////////////////////////////////////////////////////////////////////
	// Open file 
	HANDLE hFile = ::CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE) {
		assert(false && "Could not open file");
		return -1;
	}
	//TODO CLOSE HANDLE

	// Mapping Given EXE file to Memory
	HANDLE hFileMapping = ::CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if(hFileMapping == NULL) {
		assert(false && "Could not map file exe");
		return -1;
	}
	//TODO CLOSE HANDLE

	LPVOID lpBaseAddress = ::MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if(lpBaseAddress == NULL) {
		assert(false && "Map view of file fail");
		return -1;
	}
	//TODO CLOSE HANDLE

	//////////////////////////////////////////////////////////////////////////
	PIMAGE_DOS_HEADER pDOSHeader = static_cast<PIMAGE_DOS_HEADER>(lpBaseAddress);
	if(pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		assert(false && "Not PE file");
		return -1;
	}
	PIMAGE_NT_HEADERS pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((PBYTE)lpBaseAddress + pDOSHeader->e_lfanew);
	if(pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
		assert(false && "Not NT PE file");
		return -1;
	}
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>((PBYTE)&pNTHeader->OptionalHeader);
	if(IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNTHeader->OptionalHeader.Magic) {
		assert(false && "File is not 32b");
		return -1;
	}

	DWORD exeSize = pOptionalHeader->SizeOfImage;
	DebugFormat(L"EXE sizeOfImage=%u", exeSize);


	if(lpBaseAddress != NULL) { 
		::UnmapViewOfFile(lpBaseAddress);
	}
	if(hFileMapping != NULL) { 
		::CloseHandle(hFileMapping);
	}
	if(hFile != INVALID_HANDLE_VALUE) { 
		::CloseHandle(hFile);
	}

    return 0;
}
