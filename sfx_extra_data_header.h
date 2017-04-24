#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <assert.h>

class sfx_data_header
{
public:
	sfx_data_header(const uint64_t& file_modify_time, const uint32_t& file_size, const wchar_t* name)
	{
		file_modify_time_ = file_modify_time;
		file_size_ = file_size;
		file_name_.assign(name);
		file_name_size_ = (uint16_t)file_name_.size();
	}
	sfx_data_header(const uint64_t& file_modify_time, const uint32_t& file_size, const std::wstring& name)
	{
		file_modify_time_ = file_modify_time;
		file_size_ = file_size;
		file_name_.assign(name);
		file_name_size_ = (uint16_t)file_name_.size();
	}

	/* Check if read header is last one */
	bool is_terminate_header() {
		return file_size_ == 0 && file_name_size_ == 0 && header_size_ != 0;
	}

	/* Size of header and data, so we can navigate to next header */
	uint32_t size_of_current() {
		if(version_ == 1) {
			assert(header_size_ != 0 && "Function can be called only for filled data");
			assert(file_size_ != 0 && "Function can be called only for filled data");
			return header_size_ + file_size_;
		} else {
			assert(false && "Unsupported version");
			throw std::exception("Unsupported version");
		}
		return 0;
	}

	void serialize(HANDLE hFile)
	{
		if(version_ == 1) {

			DWORD writtenBytes = 0;

			header_size_ = sizeof(version_)
				+ sizeof(header_size_)
				+ sizeof(file_modify_time_)
				+ sizeof(file_size_)
				+ sizeof(file_name_size_)
				+ sizeof(wchar_t)*file_name_size_; // file_name_

			// version
			if(!::WriteFile(hFile, &version_, sizeof(version_), &writtenBytes, NULL)) {
				assert(false && "Could not write version to file");
				throw std::exception("Could not write version to file");
			}

			// header_size
			if(!::WriteFile(hFile, &header_size_, sizeof(header_size_), &writtenBytes, NULL)) {
				assert(false && "Could not write header_size to file");
				throw std::exception("Could not write header_size to file");
			}

			// file_modify_time
			if(!::WriteFile(hFile, &file_modify_time_, sizeof(file_modify_time_), &writtenBytes, NULL)) {
				assert(false && "Could not write file_modify_time size to file");
				throw std::exception("Could not write file_modify_time to file");
			}

			// file_size
			if(!::WriteFile(hFile, &file_size_, sizeof(file_size_), &writtenBytes, NULL)) {
				assert(false && "Could not write version to file");
				throw std::exception("Could not write version to file");
			}

			// name_size
			if(!::WriteFile(hFile, &file_name_size_, sizeof(file_name_size_), &writtenBytes, NULL)) {
				assert(false && "Could not write name_size to file");
				throw std::exception("Could not write name_size to file");
			}

			// name
			if(!::WriteFile(hFile, file_name_.c_str(), sizeof(wchar_t)*file_name_size_, &writtenBytes, NULL)) {
				assert(false && "Could not write name to file");
				throw std::exception("Could not write name to file");
			}
		}
	}

	void deserialize(HANDLE hFile)
	{
		DWORD readedBytes = 0;

		// version
		version_ = 0;
		if(!::ReadFile(hFile, &version_, sizeof(version_), &readedBytes, NULL)) {
			assert(false && "Could not read version to file");
			throw std::exception("Could not read version to file");
		}

		if(version_ == 1) {

			// header_size
			if(!::ReadFile(hFile, &header_size_, sizeof(header_size_), &readedBytes, NULL)) {
				assert(false && "Could not write header_size to file");
				throw std::exception("Could not write header_size to file");
			}

			// file_modify_time
			if(!::ReadFile(hFile, &file_modify_time_, sizeof(file_modify_time_), &readedBytes, NULL)) {
				assert(false && "Could not write file_modify_time size to file");
				throw std::exception("Could not write file_modify_time to file");
			}

			// file_size
			if(!::ReadFile(hFile, &file_size_, sizeof(file_size_), &readedBytes, NULL)) {
				assert(false && "Could not write version to file");
				throw std::exception("Could not write version to file");
			}

			// name_size
			if(!::ReadFile(hFile, &file_name_size_, sizeof(file_name_size_), &readedBytes, NULL)) {
				assert(false && "Could not write name_size to file");
				throw std::exception("Could not write name_size to file");
			}

			// name
			file_name_.resize(file_name_size_ + 1, L'\0');
			if(!::ReadFile(hFile, &file_name_[0], sizeof(wchar_t)*file_name_size_, &readedBytes, NULL)) {
				assert(false && "Could not write name to file");
				throw std::exception("Could not write name to file");
			}
		} else {
			assert(false && "Unsupported header version");
			throw std::exception("Unsupported header version");
		}
	}

protected:
	//////////////////////////////////////////////////////////////////////////
	// Data for header serialize
	uint8_t      version_ = 1;          // Header version
	uint32_t     header_size_ = 0;      // Header size (with all variable fields (after header file_data follow)
	uint64_t     file_modify_time_ = 0; // File modify time
	uint32_t     file_size_ = 0;        // File data size (data follow after header)
	uint16_t     file_name_size_ = 0;   // File name size
	std::wstring file_name_;            // File name (variable length)
	//////////////////////////////////////////////////////////////////////////
};