#pragma once

#include <windows.h>
#include <tchar.h>
#include "dbg.h"

namespace measure
{

class time
{
public:
	time()
	{
		::ZeroMemory(&start_, sizeof(LARGE_INTEGER));
		::ZeroMemory(&stop_, sizeof(LARGE_INTEGER));
		::ZeroMemory(&freq_, sizeof(LARGE_INTEGER));
	}
	time(const wchar_t* measure_id)
	{
		::ZeroMemory(&start_, sizeof(LARGE_INTEGER));
		::ZeroMemory(&stop_, sizeof(LARGE_INTEGER));
		::ZeroMemory(&freq_, sizeof(LARGE_INTEGER));
		start_measure(measure_id);
	}

	~time()
	{
		if(measuring_) {
			end_measure();
		}
	}

	void start_measure(const wchar_t* measure_id) {
		measuring_ = true;
		size_t id_len = wcslen(measure_id);
		wcsncpy_s(measure_id_, _countof(measure_id_), measure_id, id_len);
		::QueryPerformanceFrequency(&freq_);
		::QueryPerformanceCounter(&start_);
	}

	void end_measure(bool reset_measure = false, const wchar_t* measure_id = L"") {
		::QueryPerformanceCounter(&stop_);
		measuring_ = false;

		double dDiff;
		dDiff = double(stop_.QuadPart - start_.QuadPart);
		dDiff /= freq_.QuadPart;

		dbg::print(L"Measure [%s] time = %5.5fs\n", measure_id_, dDiff);

		if (reset_measure) {
			start_measure(measure_id);
		}
	}

private:
	bool measuring_ = false;
	LARGE_INTEGER start_, stop_, freq_;
	wchar_t measure_id_[64];
};

}; // End of namespace measure