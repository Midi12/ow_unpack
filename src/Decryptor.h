#pragma once

#include <vector>
#include <cmath>

#include "PE.h"
#include "Helpers.h"

namespace decryptor
{
	extern "C" __int16 ComputeImpl(__int64);

	bool DecryptHeader(const std::vector<char>& buffer);
	bool DecryptTextSection(const std::vector<char>& buffer);
	bool LocateXorTable(const std::vector<char>& buffer, std::uintptr_t& xtable_loc);
	bool DumpXorTable(const std::vector<char>& buffer, std::vector<char>& xtable, std::uintptr_t address, std::size_t size);
	int ComputeInitialIndex(std::uintptr_t address, std::uintptr_t sectionVA);
	void DecryptByte(std::uintptr_t address, std::ptrdiff_t offset, const std::vector<char>& xtable, int idx);
	bool DecryptPage(std::uintptr_t phys_address, std::uintptr_t virt_address, const std::vector<char>& xtable, std::uintptr_t sectionVA);
	void DecryptDword( std::uintptr_t address, const std::vector<char>& xtable, int& idx);
	bool DecryptImportDescriptor(std::uintptr_t address, const std::vector<char>& xtable, int& idx);
	bool DecryptString(std::uintptr_t address, const std::vector<char>& xtable, int& idx);
	void DecryptQword(std::uintptr_t address, const std::vector<char>& xtable, int& idx);
	bool DecryptImportByName(std::uintptr_t address, const std::vector<char>& xtable, int& idx);
	bool RenameFakeTextSection(const std::vector<char>& buffer);
	bool RemoveObfuscationLayer(const std::vector<char>& buffer);
}

