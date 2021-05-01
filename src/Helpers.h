#pragma once
#include <Windows.h>

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <functional>
#include <algorithm>
#include <exception>

namespace helpers
{
	template<typename T>
	inline std::string ToHexString(T number)
	{
		std::stringstream stream;
		stream << std::hex << number;
		return stream.str();
	}

	bool ReadFileToBuffer(std::string filename, std::vector<std::uint8_t>& buffer);
	std::uintptr_t RVAToFileOffset(PIMAGE_NT_HEADERS pNtHeaders, DWORD RelativeVirtualAddress);
	std::uintptr_t FileOffsetToRVA(PIMAGE_NT_HEADERS pNtHeaders, DWORD Offset);
	std::uintptr_t RelativeToAbsolute(std::uintptr_t address, std::ptrdiff_t rva, std::size_t inst_size);
	void FindPattern(std::uintptr_t start, std::size_t lenght, int position, const std::string& pattern, std::vector<std::uintptr_t>& results, std::function<std::uintptr_t(std::uintptr_t p)> func);
	void FindPattern(std::uintptr_t start, std::size_t lenght, int position, const std::string& pattern, std::vector<std::uintptr_t>& results, std::function<std::uintptr_t(std::uintptr_t p)> func, bool relative);
}
