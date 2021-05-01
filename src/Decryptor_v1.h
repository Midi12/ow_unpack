#pragma once

#include <vector>
#include <cstdint>
#include <cmath>
#include <algorithm>

#include "PE.h"
#include "Helpers.h"
#include "XorTable.h"

namespace decryptor_v1
{
	// data stuff
	bool GatherData(const std::vector<std::uint8_t>& buffer, XorTable& xtable);
	std::uintptr_t LocateXorTable(const std::vector<std::uint8_t>& buffer);
	std::size_t ComputeXorTableSize(const std::vector<std::uint8_t>& buffer, std::uintptr_t xtbl_address);
	bool DumpXorTable(const std::vector<std::uint8_t>& buffer, XorTable& xtable, std::uintptr_t xtbl_address, std::size_t xtbl_size);

	// misc stuff
	bool RenameFakeTextSection(const std::vector<std::uint8_t>& buffer);
	
	// header stuff
	bool DecryptHeader(const std::vector<std::uint8_t>& buffer, XorTable& xtable);

	void DecryptDword(std::uintptr_t address, XorTable & xtable, int & idx);

	bool DecryptImportDescriptor(std::uintptr_t address, XorTable & xtable, int & idx);

	bool DecryptString(std::uintptr_t address, XorTable & xtable, int & idx);

	void DecryptQword(std::uintptr_t address, XorTable & xtable, int & idx);

	bool DecryptImportByName(std::uintptr_t address, XorTable & xtable, int & idx);

	// text section stuff
	bool DecryptTextSection(const std::vector<std::uint8_t>& buffer, XorTable & xtable);

	bool DecryptPage(std::uintptr_t phys_address, std::uintptr_t virt_address, XorTable & xtable, std::uintptr_t sectionVA);

	// obfuscation stuff
	bool RemoveObfuscationLayer(const std::vector<std::uint8_t>& buffer);
}
