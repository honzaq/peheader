// peheader.cpp : Defines the entry point for the console application.
//

#include <windows.h>
#include <tchar.h>
#include <assert.h>
#include <cstdint>
#include <time.h>
#include <string>
#include "time_measure.h"
#include <vector>
#include "dbg.h"
#include "sfx_extra_data_header.h"

std::wstring gen_random_str(size_t len)
{
	static const wchar_t alphanum[] =
		L"0123456789"
		L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		L"abcdefghijklmnopqrstuvwxyz";
	const size_t alphanum_len = _countof(alphanum) - 1;
	
	std::wstring name;
	
	for (size_t i = 0; i < len; ++i) {
		name += alphanum[rand() % alphanum_len];
	}

	return name;
}

void read_data(const wchar_t* fileName)
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
			dbg::print(L"No extra data after EXE file.\n");
		}

		if (exeSize > fileSize) {
			assert(false && "exeSize is bigger than fileSize");
			break;
		}

		dbg::print(L"EXE size(the END)=%u\n", exeSize);

		if(::SetFilePointer(hFile, exeSize, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
			assert(false && "Could not set pointer to end of file");
			break;
		}

		std::vector<sfx_data_header> headers;
		DWORD newFilePos = exeSize;
		measure::time read_headers(L"read_headers");

		try
		{
			do {
			
				sfx_data_header header(0, 0, L"");
				header.deserialize(hFile);

				if (header.is_terminate_header()) {
					// END EXTRA DATA
					break;
				}

				headers.push_back(header);
			
				//////////////////////////////////////////////////////////////////////////
				// Skip read file
				//////////////////////////////////////////////////////////////////////////

				// Move to next header
				newFilePos += header.size_of_current();
				if (::SetFilePointer(hFile, newFilePos, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
					assert(false && "Could not set pointer to end of file");
					break;
				}

			} while (true);
		}
		catch (const std::exception&)
		{
			dbg::print(L"Read sfx extra files end with exception\n");
			break;
		}

		dbg::print(L"Read headers count=%u\n", (DWORD)headers.size());

		read_headers.end_measure();

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

void write_data_to_file(HANDLE hFile, const uint32_t& file_size)
{
	// Empty data
	BYTE* pData = new BYTE[file_size];
	memset(pData, 0xBB, sizeof(BYTE)*file_size);

	// Write Data
	DWORD writtenBytes = 0;
	if (!::WriteFile(hFile, pData, file_size, &writtenBytes, NULL)) {
		assert(false && "Could not write data to file");
		delete pData;
		throw std::exception("Could not set pointer to end of file");
	}
	delete pData;
}

void write_data(const wchar_t* fileName)
{
	HANDLE hFile = nullptr;
	HANDLE hFileMapping = nullptr;
	LPVOID lpBaseAddress = nullptr;
	bool set_new_end_of_file = false;
	do
	{
		//////////////////////////////////////////////////////////////////////////
		// Open file 
		hFile = ::CreateFile(fileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if(hFile == INVALID_HANDLE_VALUE) {
			assert(false && "Could not open file");
			break;
		}
		DWORD fileSize = ::GetFileSize(hFile, NULL);

		// Mapping Given EXE file to Memory
		hFileMapping = ::CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if(hFileMapping == NULL) {
			assert(false && "Could not map file exe");
			break;
		}

		lpBaseAddress = ::MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
		if(lpBaseAddress == NULL) {
			assert(false && "Map view of file fail");
			break;
		}

		//////////////////////////////////////////////////////////////////////////

		// We want file end of exe file by same method as read, 
		//  because after normal end may be signature and by this we will overwrite it
		//  also if we write all data we will call ::SetEndOfFile, to set new file end 
		//   (because may write less the signature size)

		PIMAGE_DOS_HEADER pDOSHeader = static_cast<PIMAGE_DOS_HEADER>(lpBaseAddress);
		if(pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			assert(false && "Not PE file");
			break;
		}
		PIMAGE_NT_HEADERS pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((PBYTE)lpBaseAddress + pDOSHeader->e_lfanew);
		if(pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
			assert(false && "Not NT PE file");
			break;
		}
		PIMAGE_OPTIONAL_HEADER pOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>((PBYTE)&pNTHeader->OptionalHeader);
		if(IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNTHeader->OptionalHeader.Magic) {
			assert(false && "File is not 32b");
			break;
		}
		PIMAGE_SECTION_HEADER pSECTIONHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>((PBYTE)pNTHeader + sizeof(IMAGE_NT_HEADERS));

		DWORD exeSize = 0;
		DWORD maxpointer = 0;
		for(WORD i = 0; i < pNTHeader->FileHeader.NumberOfSections; ++i) {
			if(pSECTIONHeader->PointerToRawData > maxpointer) {
				maxpointer = pSECTIONHeader->PointerToRawData;
				exeSize = pSECTIONHeader->PointerToRawData + pSECTIONHeader->SizeOfRawData;
			}
			pSECTIONHeader++;
		}

		// Test that data exist
		if(fileSize == exeSize) {
			dbg::print(L"No extra data after EXE file.\n");
		}

		if (::SetFilePointer(hFile, exeSize, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
			assert(false && "Could not set pointer to 'end' of file");
			break;
		}

		for (int testFiles = 0; testFiles < 5000; ++testFiles) {

			// Generate secret number between 1 and 30
 			int fileNameLen = rand() % 30 + 1;
			std::wstring name = gen_random_str(fileNameLen);
			uint32_t file_size = rand() % 100000 + 1;
			uint64_t modify_time = time(NULL);

			try
			{
				sfx_data_header header(modify_time, file_size, name);
				header.serialize(hFile);
				write_data_to_file(hFile, file_size);
			}
			catch (const std::exception&)
			{
				dbg::print(L"Exception in write\n");
				break;
			}
		}

		// Write terminate header
		try
		{
			sfx_data_header header(0, 0, L"");
			header.serialize(hFile);
		}
		catch (const std::exception&)
		{
			dbg::print(L"Exception in write terminate header\n");
			break;
		}

		// If all succeed we want set new end of file (for some cases not needed, but its simplier this way)
		set_new_end_of_file = true;

	} while (false);

	if(lpBaseAddress != NULL) {
		::UnmapViewOfFile(lpBaseAddress);
	}
	if(hFileMapping != NULL) {
		::CloseHandle(hFileMapping);
	}
	if(set_new_end_of_file) {
		// UnmapViewOfFile and CloseHandle on mapped file must be called first
		::SetEndOfFile(hFile);
	}
	if (hFile != INVALID_HANDLE_VALUE) {
		::CloseHandle(hFile);
	}
}

int _tmain(int argc, const _TCHAR* argv[])
{
	if(argc < 3) {
		assert(false && "Missing file path argument");
		return -1;
	}

	// init random generator
	srand((unsigned int)time(NULL));

	if (wcscmp(argv[1], L"-w") == 0) {
		// Write after EXE
		write_data(argv[2]);
	}
	else if (wcscmp(argv[1], L"-r") == 0) {
		// Read file structure after EXE
		read_data(argv[2]);
	}
	

    return 0;
}
