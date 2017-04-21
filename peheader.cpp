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

inline void debug_format(const TCHAR* szFormat, ...)
{
	TCHAR szBuff[1024];
	memset(szBuff, 0, sizeof(szBuff));

	va_list arg;
	va_start(arg, szFormat);
	_vsntprintf_s(szBuff, sizeof(szBuff) / sizeof(TCHAR), _TRUNCATE, szFormat, arg);
	va_end(arg);

	::OutputDebugString(szBuff);
};

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


class payload_header
{
public:
	payload_header(const uint64_t& file_modify_time, const uint32_t& file_size, const wchar_t* name)
	{
		file_modify_time_ = file_modify_time;
		file_size_ = file_size;
		file_name_.assign(name);
		file_name_size_ = (uint16_t)file_name_.size();
	}
	payload_header(const uint64_t& file_modify_time, const uint32_t& file_size, const std::wstring& name)
	{
		file_modify_time_ = file_modify_time;
		file_size_ = file_size;
		file_name_.assign(name);
		file_name_size_ = (uint16_t)file_name_.size();
	}

	bool is_terminate_header() {
		return file_size_ == 0 && file_name_size_ == 0 && header_size_ != 0;
	}

	uint32_t get_next_header_pointer() {
		if (version_ == 1) {
			assert(header_size_ != 0 && "Functino can be called only for filled data");
			assert(file_size_ != 0 && "Functino can be called only for filled data");
			return header_size_ + file_size_;

		}
		else {
			assert(false && "Unsupported version");
			throw std::exception("Unsupported version");
		}
		return 0;
	}

	void Serialize(HANDLE hFile)
	{
		if (version_ == 1)
		{
			DWORD writtenBytes = 0;

			header_size_ = sizeof(version_) 
				+ sizeof(header_size_) 
				+ sizeof(file_modify_time_) 
				+ sizeof(header_size_) 
				+ sizeof(file_name_size_) 
				+ sizeof(wchar_t)*file_name_size_;
			
			// version
			if (!::WriteFile(hFile, &version_, sizeof(version_), &writtenBytes, NULL)) {
				assert(false && "Could not write version to file");
				throw std::exception("Could not write version to file");
			}

			// header_size
			if (!::WriteFile(hFile, &header_size_, sizeof(header_size_), &writtenBytes, NULL)) {
				assert(false && "Could not write header_size to file");
				throw std::exception("Could not write header_size to file");
			}

			// file_modify_time
			if (!::WriteFile(hFile, &file_modify_time_, sizeof(file_modify_time_), &writtenBytes, NULL)) {
				assert(false && "Could not write file_modify_time size to file");
				throw std::exception("Could not write file_modify_time to file");
			}

			// file_size
			if (!::WriteFile(hFile, &file_size_, sizeof(file_size_), &writtenBytes, NULL)) {
				assert(false && "Could not write version to file");
				throw std::exception("Could not write version to file");
			}

			// name_size
			if (!::WriteFile(hFile, &file_name_size_, sizeof(file_name_size_), &writtenBytes, NULL)) {
				assert(false && "Could not write name_size to file");
				throw std::exception("Could not write name_size to file");
			}

			// name
			if (!::WriteFile(hFile, file_name_.c_str(), sizeof(wchar_t)*file_name_size_, &writtenBytes, NULL)) {
				assert(false && "Could not write name to file");
				throw std::exception("Could not write name to file");
			}
		}
		
		
	}
	void Deserialize(HANDLE hFile)
	{
		DWORD readedBytes = 0;
		
		// version
		version_ = 0;
		if (!::ReadFile(hFile, &version_, sizeof(version_), &readedBytes, NULL)) {
			assert(false && "Could not read version to file");
			throw std::exception("Could not read version to file");
		}

		if (version_ == 1) {

			// header_size
			if (!::ReadFile(hFile, &header_size_, sizeof(header_size_), &readedBytes, NULL)) {
				assert(false && "Could not write header_size to file");
				throw std::exception("Could not write header_size to file");
			}

			// file_modify_time
			if (!::ReadFile(hFile, &file_modify_time_, sizeof(file_modify_time_), &readedBytes, NULL)) {
				assert(false && "Could not write file_modify_time size to file");
				throw std::exception("Could not write file_modify_time to file");
			}

			// file_size
			if (!::ReadFile(hFile, &file_size_, sizeof(file_size_), &readedBytes, NULL)) {
				assert(false && "Could not write version to file");
				throw std::exception("Could not write version to file");
			}

			// name_size
			if (!::ReadFile(hFile, &file_name_size_, sizeof(file_name_size_), &readedBytes, NULL)) {
				assert(false && "Could not write name_size to file");
				throw std::exception("Could not write name_size to file");
			}

			// name
			file_name_.resize(file_name_size_ + 1, L'\0');
			if (!::ReadFile(hFile, &file_name_[0], sizeof(wchar_t)*file_name_size_, &readedBytes, NULL)) {
				assert(false && "Could not write name to file");
				throw std::exception("Could not write name to file");
			}
		}
		else
		{
			assert(false && "Unsupported payload header version");
			throw std::exception("Unsupported payload header version");
		}
	}

protected:
	uint8_t      version_          = 1; // Header version
	uint32_t     header_size_      = 0; // Header size (with all variable fields (after header file_data follow)
	uint64_t     file_modify_time_ = 0; // File modify time
	uint32_t     file_size_        = 0; // File data size (data follow after header)
	uint16_t     file_name_size_   = 0; // File name size
	std::wstring file_name_;            // File name (variable length)
};

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
			debug_format(L"No extra data after EXE file.\n");
		}

		if (exeSize > fileSize) {
			assert(false && "exeSize is bigger than fileSize");
			break;
		}

		debug_format(L"EXE size(the END)=%u\n", exeSize);

		// TODO: if sign already attached we must remove it, currently expect file is not signed

		if(::SetFilePointer(hFile, exeSize, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
			assert(false && "Could not set pointer to end of file");
			break;
		}

		// TODO

		std::vector<payload_header> headers;
		DWORD newFilePos = exeSize;
		measure::time read_headers(L"read_headers");

		try
		{
			do {
			
				payload_header header(0, 0, L"");
				header.Deserialize(hFile);

				if (header.is_terminate_header()) {
					// END EXTRA DATA
					break;
				}

				headers.push_back(header);
			
				//////////////////////////////////////////////////////////////////////////
				// Skip read file
				//////////////////////////////////////////////////////////////////////////

				// Move to next header
				newFilePos += header.get_next_header_pointer();
				if (::SetFilePointer(hFile, newFilePos, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
					assert(false && "Could not set pointer to end of file");
					break;
				}

			} while (true);
		}
		catch (const std::exception&)
		{
			break;
		}

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
	if(::SetFilePointer(hFile, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER) {
		assert(false && "Could not set pointer to end of file");
		delete pData;
		throw std::exception("Could not set pointer to end of file");
	}
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
	do
	{

		//////////////////////////////////////////////////////////////////////////
		// Open file 
		hFile = ::CreateFile(fileName, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			assert(false && "Could not open file");
			break;
		}

		if (::SetFilePointer(hFile, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER) {
			assert(false && "Could not set pointer to end of file");
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
				payload_header header(modify_time, file_size, name);
				header.Serialize(hFile);
				write_data_to_file(hFile, file_size);
			}
			catch (const std::exception&)
			{
				break;
			}
		}

		// Write terminate header
		try
		{
			payload_header header(0, 0, L"");
			header.Serialize(hFile);
		}
		catch (const std::exception&)
		{
			break;
		}

	} while (false);

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

	srand((unsigned int)time(NULL));

	if (wcscmp(argv[1], L"-w") == 0) {
		write_data(argv[2]);
	}
	else if (wcscmp(argv[1], L"-r") == 0) {
		read_data(argv[2]);
	}
	

    return 0;
}
