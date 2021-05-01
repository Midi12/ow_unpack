#include "Helpers.h"

namespace helpers
{
	bool ReadFileToBuffer(std::string filename, std::vector<std::uint8_t>& buffer)
	{
		std::ifstream in(filename, std::ios::binary);

		if (!in.good())
			return false;

		in.seekg(0, in.end);
		std::ifstream::pos_type length = in.tellg();

		std::vector<char> tmp;

		buffer.resize(length);
		tmp.resize(length);
		
		in.seekg(0, in.beg);
		in.read(tmp.data(), length);
		in.close();

		buffer.assign(tmp.begin(), tmp.end());

		return true;
	}

	std::uintptr_t RVAToFileOffset(PIMAGE_NT_HEADERS pNtHeaders, DWORD RelativeVirtualAddress)
	{
		// Get pointer on PE Section Header
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE *)pNtHeaders + sizeof(IMAGE_FILE_HEADER) + 4 + pNtHeaders->FileHeader.SizeOfOptionalHeader); // 4 byte offset to handle the Signature field in _IMAGE_NT_HEADERS

																																										  // Get number of sections
		WORD numberOfSections = pNtHeaders->FileHeader.NumberOfSections;

		// Determine in which section points RVA
		int i = 0;
		PIMAGE_SECTION_HEADER pSection = nullptr;

		// Iterate sections
		while (i < numberOfSections && !pSection)
		{
			if (RelativeVirtualAddress >= pSectionHeader->VirtualAddress && RelativeVirtualAddress < (pSectionHeader->VirtualAddress + (pSectionHeader->Misc.VirtualSize == 0 ? pSectionHeader->SizeOfRawData : pSectionHeader->Misc.VirtualSize)))
				pSection = pSectionHeader;

			i++;
			pSectionHeader++;
		}

		if (i >= numberOfSections || !pSection)
			return 0;

		// Compute file offset
		std::uintptr_t r = (RelativeVirtualAddress - pSection->VirtualAddress) + pSection->PointerToRawData;
		return r;
	}

	std::uintptr_t FileOffsetToRVA(PIMAGE_NT_HEADERS pNtHeaders, DWORD Offset)
	{
		// Get pointer on PE Section Header
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE *)pNtHeaders + sizeof(IMAGE_FILE_HEADER) + 4 + pNtHeaders->FileHeader.SizeOfOptionalHeader); // 4 byte offset to handle the Signature field in _IMAGE_NT_HEADERS

																																										  // Get number of sections
		WORD numberOfSections = pNtHeaders->FileHeader.NumberOfSections;

		// Determine in which section points RVA
		int i = 0;
		PIMAGE_SECTION_HEADER pSection = nullptr;

		// Iterate sections
		while (i < numberOfSections && !pSection)
		{
			if (Offset >= pSectionHeader->PointerToRawData && Offset < (pSectionHeader->PointerToRawData + (pSectionHeader->SizeOfRawData == 0 ? pSectionHeader->Misc.VirtualSize : pSectionHeader->SizeOfRawData)))
				pSection = pSectionHeader;

			i++;
			pSectionHeader++;
		}

		if (i >= numberOfSections || !pSection)
			return 0;

		// Compute file offset
		std::uintptr_t r = (Offset + pSection->VirtualAddress) - pSection->PointerToRawData;
		return r;
	}

	void FindPattern(std::uintptr_t start, std::size_t lenght, int position, const std::string& pattern, std::vector<std::uintptr_t>& results, std::function<std::uintptr_t(std::uintptr_t p)> func)
	{
		if (pattern.empty())
			return;

		//credit : darthton blackbone source
		const std::uint8_t *cstart = (const std::uint8_t *)start;
		const std::uint8_t *cend = cstart + lenght;

		const std::uint8_t wildcard = 0xCC;
		std::vector<std::uint8_t> vpattern;

		const char delimiter = ' ';

		// setup pattern
		std::vector<std::string> tokens;
		std::string token;

		std::stringstream ss(pattern);

		while (std::getline(ss, token, delimiter))
		{
			if (token == "??")
				vpattern.emplace_back(wildcard);
			else
			{
				std::istringstream hex(token);
				std::uint32_t byte;
				hex >> std::hex >> byte;

				vpattern.emplace_back(byte);
			}
		}

		for (;;)
		{
			const std::uint8_t *res = std::search(cstart, cend, vpattern.begin(), vpattern.end(),
				[&wildcard](std::uint8_t v1, std::uint8_t v2)
			{
				return (v1 == v2 || v2 == wildcard);
			});

			if (res >= cend)
				break;

			if (position != 0)
				res = res + position;

			if (func)
			{
				std::uintptr_t newAddr = func(reinterpret_cast<std::uintptr_t>(res));
				results.emplace_back(newAddr);
			}
			else
				results.emplace_back(reinterpret_cast<std::uintptr_t>(res));

			cstart = res + vpattern.size();
		}
	}

	void FindPattern(std::uintptr_t start, std::size_t lenght, int position, const std::string& pattern, std::vector<std::uintptr_t>& results, std::function<std::uintptr_t(std::uintptr_t p)> func, bool relative)
	{
		if(relative)
			FindPattern(start, lenght, position, pattern, results,
				[&](std::uintptr_t p) -> std::uintptr_t
				{
					std::uintptr_t offset = p - start;

					if (offset + 4 >= start + lenght)
						throw std::out_of_range("rva");

					int relAddr = *(int*)&((const std::uint8_t *)start)[offset];
					return p + 4 + relAddr;
				});
		else
			FindPattern(start, lenght, position, pattern, results, nullptr);
	}

	std::uintptr_t RelativeToAbsolute(std::uintptr_t address, std::ptrdiff_t rva, std::size_t inst_size)
	{
		return address + rva + inst_size;
	}
}