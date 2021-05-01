#pragma once

#include <Windows.h>

namespace pe
{
	bool IsValidDosHeader(LPVOID ptr);
	bool IsValidNtHeaders(LPVOID ptr);
	PIMAGE_NT_HEADERS GetNtHeaders(LPVOID ptr);
	PIMAGE_SECTION_HEADER GetSection(LPVOID ptr, unsigned __int64 name);
}

