#pragma once

#include <tchar.h>
#include <windows.h>

namespace dbg
{

inline void print(const TCHAR* szFormat, ...)
{
	TCHAR szBuff[1024];
	memset(szBuff, 0, sizeof(szBuff));

	va_list arg;
	va_start(arg, szFormat);
	_vsntprintf_s(szBuff, sizeof(szBuff) / sizeof(TCHAR), _TRUNCATE, szFormat, arg);
	va_end(arg);

	::OutputDebugString(szBuff);
};

inline void printa(const char* szFormat, ...)
{
	char szBuff[1024];
	memset(szBuff, 0, sizeof(szBuff));

	va_list arg;
	va_start(arg, szFormat);
	_vsnprintf_s(szBuff, sizeof(szBuff) / sizeof(char), _TRUNCATE, szFormat, arg);
	va_end(arg);

	::OutputDebugStringA(szBuff);
};

}; // End of namespace dbg
