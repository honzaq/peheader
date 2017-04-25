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
#include "cmdp.h"
#include "sfx_extra_data_header.h"
#include "scope_guard.h"

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

	//////////////////////////////////////////////////////////////////////////
	// Open file 
	hFile = ::CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		assert(false && "Could not open file");
		throw std::exception("Could not open file");
	}
	scope_guard file_guard = [&]() {
		if (hFile != INVALID_HANDLE_VALUE) {
			::CloseHandle(hFile);
		}
	};

	DWORD fileSize = ::GetFileSize(hFile, NULL);

	//////////////////////////////////////////////////////////////////////////
	// Mapping Given EXE file to Memory
	hFileMapping = ::CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == NULL) {
		assert(false && "Could not map file exe");
		throw std::exception("Could not map file exe");
	}
	scope_guard filemap_guard = [&]() {
		if (hFileMapping != NULL) {
			::CloseHandle(hFileMapping);
		}
	};

	lpBaseAddress = ::MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpBaseAddress == NULL) {
		assert(false && "Map view of file fail");
		throw std::exception("Map view of file fail");
	}
	scope_guard filemapview_guard = [&]() {
		if (lpBaseAddress != NULL) {
			::UnmapViewOfFile(lpBaseAddress);
		}
	};

	//////////////////////////////////////////////////////////////////////////
	PIMAGE_DOS_HEADER pDOSHeader = static_cast<PIMAGE_DOS_HEADER>(lpBaseAddress);
	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		assert(false && "Not PE file");
		throw std::exception("Not PE file");
	}
	PIMAGE_NT_HEADERS pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((PBYTE)lpBaseAddress + pDOSHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
		assert(false && "Not NT PE file");
		throw std::exception("Not NT PE file");
	}
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>((PBYTE)&pNTHeader->OptionalHeader);
	if (IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNTHeader->OptionalHeader.Magic) {
		assert(false && "File is not 32b");
		throw std::exception("File is not 32b");
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
		dbg::print(L"No extra data after EXE file.\n");
	}
	else {
		dbg::print(L"Found extra data.\n");
	}

	if (exeSize > fileSize) {
		assert(false && "exeSize is bigger than fileSize");
		throw std::exception("exeSize is bigger than fileSize");
	}

	if(::SetFilePointer(hFile, exeSize, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		assert(false && "Could not set pointer to new position");
		throw std::exception("Could not set pointer to new position");
	}

	std::vector<sfx_data_header> headers;
	DWORD newFilePos = exeSize;
	measure::time read_headers(L"read_headers");

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

		if (newFilePos > fileSize) {
			assert(false && "Setting pointer after end of file");
			throw std::exception("Setting pointer after end of file");
		}

		if (::SetFilePointer(hFile, newFilePos, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
			assert(false && "Could not set pointer to new position");
			throw std::exception("Could not set pointer to new position");
		}

	} while (true);

	read_headers.end_measure();

	dbg::print(L"Read headers count=%u\n", (DWORD)headers.size());
	for (const auto& header : headers) {
		dbg::print(L" * found file=%s ; %u ; %llx ; \n", header.file_name().c_str(), header.file_size(), header.file_modify_time());
	}
}

void write_data_to_file(HANDLE hFile, const uint32_t& file_size)
{
	// Empty data
	BYTE* pData = new BYTE[file_size];
	memset(pData, 0xBB, sizeof(BYTE)*file_size);

	scope_guard data_guard = [&]() {
		delete pData;
	};

	// Write Data
	DWORD writtenBytes = 0;
	if (!::WriteFile(hFile, pData, file_size, &writtenBytes, NULL)) {
		assert(false && "Could not write data to file");
		throw std::exception("Could not set pointer to end of file");
	}
}

std::vector<std::wstring> split(const wchar_t* str, wchar_t splitter = L';')
{
	std::vector<std::wstring> result;

	do
	{
		const wchar_t* begin = str;

		while (*str != splitter && *str) {
			str++;
		}

		result.push_back(std::wstring(begin, str));
	} while (0 != *str++);

	return result;
}

void add_random_file(HANDLE hFile)
{
	// Generate secret number between 1 and 30
	int fileNameLen = rand() % 30 + 1;
	std::wstring name = gen_random_str(fileNameLen);
	uint32_t file_size = rand() % 100000 + 1;
	uint64_t modify_time = time(NULL);

	sfx_data_header header(modify_time, file_size, name);
	header.serialize(hFile);
	write_data_to_file(hFile, file_size);
}

void add_file(HANDLE hFile, const std::wstring& name)
{
	HANDLE hReadFile = ::CreateFile(name.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		assert(false && "Could not open file");
		throw std::exception("Could not open file");
	}

	scope_guard file_guard = [&]() {
		if (hReadFile != INVALID_HANDLE_VALUE) {
			::CloseHandle(hReadFile);
		}
	};

	// Get file last modify time
	FILETIME creationTime, lastAccessTime, lastWriteTime;
	if (!::GetFileTime(hReadFile, &creationTime, &lastAccessTime, &lastWriteTime)) {
		assert(false && "Could not read file size");
		throw std::exception("Could not read file size");
	}

	uint64_t modify_time = (static_cast<uint64_t>(lastWriteTime.dwHighDateTime) << 32) | lastWriteTime.dwLowDateTime;
	uint32_t file_size = ::GetFileSize(hReadFile, NULL);

	dbg::print(L" * new file=%s ; %u ; %llx ; \n", name.c_str(), file_size, modify_time);

	// Write header
	sfx_data_header header(modify_time, file_size, name);
	header.serialize(hFile);

	// Copy file
	static BYTE copy_buffer[4096];

	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;
	do
	{
		if (!::ReadFile(hReadFile, copy_buffer, sizeof(copy_buffer), &dwBytesRead, NULL)) {
			assert(false && "Could not read data from file");
			throw std::exception("Could not read data from file");
		}
		if (dwBytesRead == 0) {
			break; // End of file
		}
		if (!::WriteFile(hFile, copy_buffer, dwBytesRead, &dwBytesWritten, NULL)) {
			assert(false && "Could not write data to file");
			throw std::exception("Could not write data to file");
		}
	} while(true);
}

void write_data(const wchar_t* fileName, const wchar_t* list_of_files)
{
	HANDLE hFile = nullptr;
	HANDLE hFileMapping = nullptr;
	LPVOID lpBaseAddress = nullptr;
	bool set_new_end_of_file = false;

	bool random_files = true;

	//////////////////////////////////////////////////////////////////////////
	// Parse list_of_files
	std::vector<std::wstring> files_to_add;
	if (list_of_files != nullptr) {
		files_to_add = split(list_of_files);
		if (files_to_add.size() > 0) {
			random_files = false;
		}
	}

	//////////////////////////////////////////////////////////////////////////
	// Open file 
	hFile = ::CreateFile(fileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE) {
		assert(false && "Could not open file");
		throw std::exception("Could not open file");
	}
	scope_guard file_guard = [&]() {
		if (set_new_end_of_file) {
			// UnmapViewOfFile and CloseHandle on mapped file must be called first
			::SetEndOfFile(hFile);
		}
		if (hFile != INVALID_HANDLE_VALUE) {
			::CloseHandle(hFile);
		}
	};

	DWORD fileSize = ::GetFileSize(hFile, NULL);

	//////////////////////////////////////////////////////////////////////////
	// Mapping Given EXE file to Memory
	hFileMapping = ::CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if(hFileMapping == NULL) {
		assert(false && "Could not map file exe");
		throw std::exception("Could not map file exe");
	}
	scope_guard filemap_guard = [&]() {
		if (hFileMapping != NULL) {
			::CloseHandle(hFileMapping);
		}
	};

	lpBaseAddress = ::MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if(lpBaseAddress == NULL) {
		assert(false && "Map view of file fail");
		throw std::exception("Map view of file fail");
	}
	scope_guard filemapview_guard = [&]() {
		if (lpBaseAddress != NULL) {
			::UnmapViewOfFile(lpBaseAddress);
		}
	};

	//////////////////////////////////////////////////////////////////////////

	// We want file end of exe file by same method as read, 
	//  because after normal end may be signature and by this we will overwrite it
	//  also if we write all data we will call ::SetEndOfFile, to set new file end 
	//   (because may write less the signature size)

	PIMAGE_DOS_HEADER pDOSHeader = static_cast<PIMAGE_DOS_HEADER>(lpBaseAddress);
	if(pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		assert(false && "Not PE file");
		throw std::exception("Not PE file");
	}
	PIMAGE_NT_HEADERS pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((PBYTE)lpBaseAddress + pDOSHeader->e_lfanew);
	if(pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
		assert(false && "Not NT PE file");
		throw std::exception("Not NT PE file");
	}
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>((PBYTE)&pNTHeader->OptionalHeader);
	if(IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNTHeader->OptionalHeader.Magic) {
		assert(false && "File is not 32b");
		throw std::exception("File is not 32b");
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
	else {
		dbg::print(L"EXE contains extra data, but will be overwritten.\n");
	}

	if (::SetFilePointer(hFile, exeSize, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		assert(false && "Could not set pointer to new position");
		throw std::exception("Could not set pointer to new position");
	}

	size_t files_count = random_files ? 5000 : files_to_add.size();

	for(auto testFiles = 0U; testFiles < files_count; ++testFiles) {

		if (random_files) {
			add_random_file(hFile);
		}
		else {
			add_file(hFile, files_to_add[testFiles]);
		}
	}

	// Write terminate header
	sfx_data_header header(0, 0, L"");
	header.serialize(hFile);

	// If all succeed we want set new end of file (for some cases not needed, but its simplier this way)
	set_new_end_of_file = true;
}

int _tmain(int argc, const _TCHAR* argv[])
{
	// init random generator
	srand((unsigned int)time(NULL));

	cmdp::parser cmdp(argc, argv);
	
	if (cmdp[L"w"]) { // Write after EXE
		// Parameter of --w parameter should be path to EXE file.
		//  second param is files="<path>;<path2>...."
		try
		{
			// -w c:\download\1.exe -files="c:\download\test1.zip;c:\download\test2.zip"
			write_data(cmdp(L"w").str().c_str(), cmdp[L"files"] ? cmdp(L"files").str().c_str() : nullptr);
		}
		catch (const std::exception& e)
		{
			dbg::printa("Exception during write '%s'", e.what());
			return 1;
		}
	}
	else if (cmdp[L"r"]) { // Read file structure after EXE
		
		// Parameter of --r parameter should be path to EXE file
		try
		{
			// -r c:\download\1.exe
			read_data(cmdp(L"r").str().c_str());
		}
		catch (const std::exception& e)
		{
			dbg::printa("Exception during read '%s'", e.what());
			return 2;
		}
	}

    return 0;
}
