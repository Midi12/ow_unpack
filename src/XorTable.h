#pragma once

#include <cstdint>
#include <vector>

class XorTable
{
public:
	XorTable();
	~XorTable();

	bool IsValid(void) const;
	
	std::uintptr_t GetAddress(void) const;
	std::vector<std::uint8_t>& GetData(void);
	std::size_t GetSize(void) const;
	std::uint32_t GetIModulo(void) const;
	std::uint32_t GetXModulo(void) const;

	void SetAddress(std::uintptr_t address);
	void SetSize(std::size_t size);
	void SetIModulo(std::uint32_t imod);
	void SetXModulo(std::uint32_t xmod);

	std::uint32_t ComputeInitialIndex(std::uintptr_t address, std::uintptr_t section_va) const;

private:
	std::uintptr_t mAddress;
	std::vector<std::uint8_t> mData;
	std::size_t mSize;
	std::uint32_t mIModulo;
	std::uint32_t mXModulo;
};

