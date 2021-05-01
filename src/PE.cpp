#include "PE.h"

namespace pe
{
	bool IsValidDosHeader(LPVOID ptr)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ptr;

		return pDosHeader->e_magic == 'ZM';
	}

	bool IsValidNtHeaders(LPVOID ptr)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ptr;

		if (!IsValidDosHeader(pDosHeader))
			return false;

		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE *)pDosHeader + pDosHeader->e_lfanew);

		return pNtHeaders->Signature == 'EP';
	}

	PIMAGE_NT_HEADERS GetNtHeaders(LPVOID ptr)
	{
		if (!IsValidDosHeader(ptr) || !IsValidNtHeaders(ptr))
			return nullptr;

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ptr;
		return (PIMAGE_NT_HEADERS)((BYTE *)pDosHeader + pDosHeader->e_lfanew);
	}

	PIMAGE_SECTION_HEADER GetSection(LPVOID ptr, unsigned __int64 name)
	{
		if (!IsValidDosHeader(ptr) || !IsValidNtHeaders(ptr))
			return nullptr;

		PIMAGE_NT_HEADERS pNtHeaders = GetNtHeaders(ptr);

		WORD numberOfSections = pNtHeaders->FileHeader.NumberOfSections;

		PIMAGE_SECTION_HEADER pSec = nullptr;
		PIMAGE_SECTION_HEADER pIt = (PIMAGE_SECTION_HEADER)((BYTE *)pNtHeaders + sizeof(IMAGE_FILE_HEADER) + 4 + pNtHeaders->FileHeader.SizeOfOptionalHeader); // 4 byte offset to handle the Signature field in _IMAGE_NT_HEADERS

		int i = 0;

		// Iterate sections
		while (i < numberOfSections && !pSec)
		{
			if (*(unsigned __int64 *)pIt->Name == name)
			/*if (pIt->Name[0] == sectionName[0]
				&& pIt->Name[1] == sectionName[1]
				&& pIt->Name[2] == sectionName[2]
				&& pIt->Name[3] == sectionName[3]
				&& pIt->Name[4] == sectionName[4]
				&& pIt->Name[5] == sectionName[5]
				&& pIt->Name[6] == sectionName[6]
				&& pIt->Name[7] == sectionName[7])*/
			{
				pSec = pIt;
			}

			i++;
			pIt++;
		}

		return pSec;
	}
}
