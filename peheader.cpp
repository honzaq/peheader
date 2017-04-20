// peheader.cpp : Defines the entry point for the console application.
//

#include <windows.h>
#include <tchar.h>
#include <assert.h>
#include <cstdint>
#include <time.h>

#pragma pack(push, 1)
struct payload_header
{
	uint32_t header_size;
	uint32_t file_size;
	uint64_t modify_time;
	wchar_t name[ANYSIZE_ARRAY];
};
#pragma pop

void gen_random_str(wchar_t* text, const int len)
{
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		text[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	text[len] = '\0';
}

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

void ReadData(const wchar_t* fileName)
{
	HANDLE hFile = nullptr;
	HANDLE hFileMapping = nullptr;
	LPVOID lpBaseAddress = nullptr;
	do
	{

		//////////////////////////////////////////////////////////////////////////
		// Open file 
		hFile = ::CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			assert(false && "Could not open file");
			break;
		}
		DWORD fileSize = ::GetFileSize(hFile, NULL);

		// Mapping Given EXE file to Memory
		hFileMapping = ::CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (hFileMapping == NULL) {
			assert(false && "Could not map file exe");
			break;
		}

		lpBaseAddress = ::MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
		if (lpBaseAddress == NULL) {
			assert(false && "Map view of file fail");
			break;
		}

		//////////////////////////////////////////////////////////////////////////
		PIMAGE_DOS_HEADER pDOSHeader = static_cast<PIMAGE_DOS_HEADER>(lpBaseAddress);
		if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			assert(false && "Not PE file");
			break;
		}
		PIMAGE_NT_HEADERS pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((PBYTE)lpBaseAddress + pDOSHeader->e_lfanew);
		if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
			assert(false && "Not NT PE file");
			break;
		}
		PIMAGE_OPTIONAL_HEADER pOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>((PBYTE)&pNTHeader->OptionalHeader);
		if (IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNTHeader->OptionalHeader.Magic) {
			assert(false && "File is not 32b");
			break;
		}
		PIMAGE_SECTION_HEADER pSECTIONHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>((PBYTE)pNTHeader + sizeof(IMAGE_NT_HEADERS));

		DWORD exeSize = 0;
		DWORD maxpointer = 0;
		for (WORD i = 0; i < pNTHeader->FileHeader.NumberOfSections; ++i) {
			if (pSECTIONHeader->PointerToRawData > maxpointer) {
				maxpointer = pSECTIONHeader->PointerToRawData;
				exeSize = pSECTIONHeader->PointerToRawData + pSECTIONHeader->SizeOfRawData;
			}
			pSECTIONHeader++;
		}

		// Test that data exist
		if (fileSize == exeSize) {
			// NO DATA
			DebugFormat(L"No extra data after EXE file.\n");
		}

		if (exeSize > fileSize) {
			assert(false && "exeSize is bigger than fileSize");
			break;
		}

		DebugFormat(L"EXE size(the END)=%u\n", exeSize);

		DWORD endFilePointer = ::SetFilePointer(hFile, exeSize, NULL, FILE_BEGIN);
		if (endFilePointer == INVALID_SET_FILE_POINTER) {
			assert(false && "Could not set pointer to end of file");
			break;
		}

		// TODO

	} while (false);

	if (lpBaseAddress != NULL) {
		::UnmapViewOfFile(lpBaseAddress);
	}
	if (hFileMapping != NULL) {
		::CloseHandle(hFileMapping);
	}
	if (hFile != INVALID_HANDLE_VALUE) {
		::CloseHandle(hFile);
	}
}

void WriteData(const wchar_t* fileName)
{
	srand((unsigned int)time(NULL));

	HANDLE hFile = nullptr;
	HANDLE hFileMapping = nullptr;
	LPVOID lpBaseAddress = nullptr;
	do
	{

		//////////////////////////////////////////////////////////////////////////
		// Open file 
		hFile = ::CreateFile(fileName, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			assert(false && "Could not open file");
			break;
		}

		for (int testFiles = 0; testFiles < 5000; ++testFiles) {

			DWORD endFilePointer = ::SetFilePointer(hFile, 0, NULL, FILE_END);
			if (endFilePointer == INVALID_SET_FILE_POINTER) {
				assert(false && "Could not set pointer to end of file");
				break;
			}

			/* generate secret number between 1 and 10: */
			int fileNameLen = 2;// rand() % 30 + 1;

			DebugFormat(L"sizeof(payload_header)=%u\n", sizeof(payload_header));

			payload_header* pNewHeader = (payload_header*)malloc(sizeof(payload_header) + (sizeof(wchar_t)*(fileNameLen)));
			::ZeroMemory(pNewHeader, sizeof(payload_header) + (sizeof(wchar_t)*(fileNameLen)));
			//memset(pNewHeader, 0xBB, sizeof(payload_header) + (sizeof(wchar_t)*(fileNameLen)));
			gen_random_str(&pNewHeader->name[0], fileNameLen);
			pNewHeader->header_size = sizeof(payload_header) + (fileNameLen * sizeof(wchar_t));
			pNewHeader->file_size = rand() % 100000 + 1;
			pNewHeader->modify_time = time(NULL);

			// Write header
			DWORD writtenBytes = 0;
			if (!::WriteFile(hFile, pNewHeader, pNewHeader->header_size, &writtenBytes, NULL)) {
				assert(false && "Could not write header to file");
				free(pNewHeader);
				break;
			}

			// Empty data
			BYTE* pData = new BYTE[pNewHeader->file_size];
			//::ZeroMemory(pData, sizeof(BYTE)*pNewHeader->file_size);
			memset(pData, 0xBB, sizeof(BYTE)*pNewHeader->file_size);

			// Write Data
			endFilePointer = ::SetFilePointer(hFile, 0, NULL, FILE_END);
			if (endFilePointer == INVALID_SET_FILE_POINTER) {
				assert(false && "Could not set pointer to end of file");
				free(pNewHeader);
				delete pData;
				break;
			}
			if (!::WriteFile(hFile, pData, pNewHeader->file_size, &writtenBytes, NULL)) {
				assert(false && "Could not write data to file");
				free(pNewHeader);
				delete pData;
				break;
			}
			delete pData;
			free(pNewHeader);
		}

	} while (false);

	if (lpBaseAddress != NULL) {
		::UnmapViewOfFile(lpBaseAddress);
	}
	if (hFileMapping != NULL) {
		::CloseHandle(hFileMapping);
	}
	if (hFile != INVALID_HANDLE_VALUE) {
		::CloseHandle(hFile);
	}
}

int _tmain(int argc, const _TCHAR* argv[])
{
	if(argc < 1) {
		assert(false && "Missing file path argument");
		return -1;
	}

	//ReadData(argv[1]);
	WriteData(argv[1]);

    return 0;
}
