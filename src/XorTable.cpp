#include "XorTable.h"

XorTable::XorTable() :
	mAddress(0),
	mSize(0),
	mData(),
	mIModulo(-1),
	mXModulo(-1)
{
}

XorTable::~XorTable()
{
}

bool XorTable::IsValid(void) const
{
	return this->mData.size() >= 0 && this->mIModulo != -1 && this->mXModulo != -1;
}

std::uintptr_t XorTable::GetAddress(void) const
{
	return this->mAddress;
}

std::vector<std::uint8_t>& const XorTable::GetData(void)
{
	return this->mData;
}

std::size_t XorTable::GetSize(void) const
{
	return this->mSize;
}

std::uint32_t XorTable::GetIModulo(void) const
{
	return this->mIModulo;
}

std::uint32_t XorTable::GetXModulo(void) const
{
	return this->mXModulo;
}

void XorTable::SetAddress(std::uintptr_t address)
{
	this->mAddress = address;
}

void XorTable::SetSize(std::size_t size)
{
	this->mSize = size;
}

void XorTable::SetIModulo(std::uint32_t imod)
{
	this->mIModulo = imod;
}

void XorTable::SetXModulo(std::uint32_t xmod)
{
	this->mXModulo = xmod;
}

std::uint32_t XorTable::ComputeInitialIndex(std::uintptr_t address, std::uintptr_t section_va) const
{
	return (address - section_va) / 0x1000 % this->mIModulo;
}
