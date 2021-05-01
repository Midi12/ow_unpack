#include "Main.h"
#include "Decryptor.h"

namespace decryptor
{
	bool DecryptHeader(const std::vector<char>& buffer)
	{
		LPVOID basePtr = (LPVOID)buffer.data();

		if (!pe::IsValidDosHeader(basePtr))
			return false;

		if (!pe::IsValidNtHeaders(basePtr))
			return false;

		PIMAGE_NT_HEADERS pNtHeaders = pe::GetNtHeaders(basePtr);
		if (!pNtHeaders)
			return nullptr;

		std::uintptr_t xtable_loc = 0x0;
		if (!LocateXorTable(buffer, xtable_loc))
			return false;

		std::vector<char> xtable;
		if (!DumpXorTable(buffer, xtable, helpers::RVAToFileOffset(pNtHeaders, xtable_loc), 0x1D00))
			return false;

		int index = 0;
		DecryptDword((std::uintptr_t)((BYTE *)pNtHeaders + 0x94), xtable, index);

		DWORD importsRVA_save = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
		PIMAGE_IMPORT_DESCRIPTOR firstImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)basePtr + helpers::RVAToFileOffset(pNtHeaders, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size));

		std::size_t importsSize = 0;
		std::uintptr_t pIt = (std::uintptr_t)firstImportDesc;

		do
		{
			DecryptImportDescriptor(pIt, xtable, index);

			BYTE * nameAddr = (BYTE *)basePtr + helpers::RVAToFileOffset(pNtHeaders, *(DWORD *)(pIt + 0xC));
			DecryptString((std::uintptr_t)nameAddr, xtable, index);

			std::uintptr_t importTableAddr = (std::uintptr_t)basePtr + helpers::RVAToFileOffset(pNtHeaders, *(DWORD *)(pIt + 0x0));

			std::uintptr_t pIt2 = importTableAddr;

			do
			{
				DecryptQword(pIt2, xtable, index);

				if (*(DWORD *)(pIt2 + 0x4) >> 31 == 1)
				{
					//*(DWORD *)(pIt2 + 0x4) = (*(DWORD *)(pIt2 + 0x4) << 1) >> 1;
				}
				else
				{
					DecryptImportByName((std::uintptr_t)basePtr + helpers::RVAToFileOffset(pNtHeaders, *(unsigned __int64 *)(pIt2)), xtable, index);
				}

				pIt2 += 0x8;
			} while (*(DWORD *)(pIt2) != 0x0);

			pIt += 0x14;
			importsSize += 0x14;
		} while (*(DWORD *)(pIt) != 0x0);

		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = importsRVA_save;
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (DWORD)importsSize;
	}

	bool DecryptTextSection(const std::vector<char>& buffer)
	{
		LPVOID basePtr = (LPVOID)buffer.data();

		if (!pe::IsValidDosHeader(basePtr))
			return false;

		if (!pe::IsValidNtHeaders(basePtr))
			return false;

		PIMAGE_NT_HEADERS pNtHeaders = pe::GetNtHeaders(basePtr);
		if (!pNtHeaders)
			return nullptr;

		std::uintptr_t xtable_loc = 0x0;
		if (!LocateXorTable(buffer, xtable_loc))
			return false;

		std::vector<char> xtable;
		if (!DumpXorTable(buffer, xtable, helpers::RVAToFileOffset(pNtHeaders, xtable_loc), 0x1D00))
			return false;

		PIMAGE_SECTION_HEADER pTextSec = pe::GetSection(basePtr, 0x000000747865742E/*".text\0\0\0"*/);

		std::uintptr_t va = 0x140000000 + pTextSec->VirtualAddress;
		std::uintptr_t startSec = (std::uintptr_t)basePtr + pTextSec->PointerToRawData; //+ helpers::RVAToFileOffset(pNtHeaders, pTextSec->VirtualAddress);		
		std::uintptr_t sizeSec = pTextSec->SizeOfRawData;
		std::uintptr_t endSec = startSec + sizeSec;

		std::uintptr_t currentPage = startSec;
		std::size_t pageSize = 0x1000;

		pfnSetProgressBarRange(0, 100, 1);

		while (currentPage < endSec)
		{
			//pFunc("Decrypting page 0x" + helpers::ToHexString(va) + "-0x" + helpers::ToHexString(va + pageSize) + " " + std::to_string(std::round(((float)(va - (0x140000000 + pTextSec->VirtualAddress) + pageSize) / (float)(sizeSec)) * 100.0f)) + "%");
			DecryptPage(currentPage, va, xtable, 0x140000000 + pTextSec->VirtualAddress);

			va += pageSize;
			currentPage += pageSize;
			
			pfnProgressProgressBar((float)((float)(currentPage - startSec) / endSec) * 1000);
		}

		return true;
	}

	bool LocateXorTable(const std::vector<char>& buffer, std::uintptr_t& xtable_loc)
	{
		LPVOID ptr = (LPVOID)buffer.data();
		PIMAGE_SECTION_HEADER pDataSec = pe::GetSection(ptr, 0x000000617461642E/*".data\0\0\0"*/);

		if (pDataSec == nullptr)
			return false;

		xtable_loc = pDataSec->VirtualAddress;

		return xtable_loc != 0x0;
	}

	bool DumpXorTable(const std::vector<char>& buffer, std::vector<char>& xtable, std::uintptr_t address, std::size_t size)
	{
		for (std::uintptr_t i = address; i < address + size; i++)
			xtable.emplace_back(buffer[i]);

		return true;
	}

	int ComputeInitialIndex(std::uintptr_t address, std::uintptr_t sectionVA)
	{
		__int64 base = (address - sectionVA);
		__int64 i = ComputeImpl(base);
		return i;
	}

	void DecryptByte(std::uintptr_t address, std::ptrdiff_t offset, const std::vector<char>& xtable, int idx)
	{
		*(char *)(address) = *(char *)(address) ^ xtable[idx + (offset & 0xFF)];
	}

	bool DecryptPage(std::uintptr_t phys_address, std::uintptr_t virt_address, const std::vector<char>& xtable, std::uintptr_t sectionVA)
	{
		std::uintptr_t ptr = phys_address;
		
		int idx = ComputeInitialIndex(virt_address & 0xFFFFFFFFFFFFF000, sectionVA);

		ptr = (ptr /*& 0xFFFFFFFFFFFFF000*/) + 1;
		int count = 0x400;
		int offset = 2;

		do
		{
			ptr += 4;
			DecryptByte(ptr - 5, offset - 2, xtable, idx);
			DecryptByte(ptr - 4, offset - 1, xtable, idx);
			DecryptByte(ptr - 3, offset, xtable, idx);
			int offset2 = offset + 1;
			offset += 4;
			DecryptByte(ptr - 2, offset2, xtable, idx);
			count -= 1;
		} while (count > 0);

		return true;
	}

	void DecryptDword(std::uintptr_t address, const std::vector<char>& xtable, int& idx)
	{
		std::uintptr_t ptr = address;

		do
		{
			ptr += 1;
			int offset = idx & 0xFF;
			idx += 1;
			*(char *)(ptr - 1) = *(char *)(ptr - 1) ^ xtable[offset];
		} while (idx < 4);
	}

	bool DecryptImportDescriptor(std::uintptr_t address, const std::vector<char>& xtable, int& idx)
	{
		int size = 0;
		std::uintptr_t ptr = address;

		do
		{
			ptr += 1;
			int offset = idx & 0xFF;
			size += 1;
			idx += 1;
			*(char *)(ptr - 1) = *(char *)(ptr - 1) ^ xtable[offset];
		} while (size < 0x14);

		return true;
	}

	bool DecryptString(std::uintptr_t address, const std::vector<char>& xtable, int& idx)
	{
		std::uintptr_t ptr = address;

		char first = *(char *)(ptr) ^ xtable[idx & 0xFF];
		*(char *)(ptr) = first;

		char unxored = first;

		if (first == 0x00)
			return false;
		else
		{
			do
			{
				ptr += 1;
				idx += 1;
				unxored = *(char *)(ptr) ^ xtable[idx & 0xFF];
				*(char *)(ptr) = unxored;
			} while (unxored != 0x00);
		}

		return true;
	}

	void DecryptQword(std::uintptr_t address, const std::vector<char>& xtable, int& idx)
	{
		std::uintptr_t ptr = address;
		int count = 0;

		do
		{
			*(char *)(ptr) = *(char *)(ptr) ^ xtable[idx & 0xFF];
			idx += 1;
			ptr += 1;
			count += 1;
		} while (count < 8);
	}

	bool DecryptImportByName(std::uintptr_t address, const std::vector<char>& xtable, int& idx)
	{
		return DecryptString(address + 2, xtable, idx);
	}

	bool RenameFakeTextSection(const std::vector<char>& buffer)
	{
		LPVOID basePtr = (LPVOID)buffer.data();

		if (!pe::IsValidDosHeader(basePtr))
			return false;

		if (!pe::IsValidNtHeaders(basePtr))
			return false;

		PIMAGE_SECTION_HEADER pFakeTextSec = pe::GetSection(basePtr, 0x000C00747865742E/*".text\0\f\0"*/);

		*(unsigned __int64*)pFakeTextSec->Name = 0x0072656b6361702e;

		PIMAGE_SECTION_HEADER pPackerSec = pe::GetSection(basePtr, 0x0072656b6361702e/*".packer\0"*/);

		return pPackerSec != nullptr;
	}

	bool RemoveObfuscationLayer(const std::vector<char>& buffer)
	{
		LPVOID basePtr = (LPVOID)buffer.data();

		if (!pe::IsValidDosHeader(basePtr))
			return false;

		if (!pe::IsValidNtHeaders(basePtr))
			return false;

		static std::vector<std::uint8_t> lpush = { 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57 };
		static std::vector<std::uint8_t> lop = { 0xc8, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe5, 0xe6, 0xe7, 0xf0, 0xf1, 0xf2, 0xf3, 0xf6, 0xf5, 0xf7 };
		static std::vector<std::uint8_t> lpop = { 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f };
		static std::vector<std::uint8_t> lbranch = { 0x71, 0x73 };

		PIMAGE_SECTION_HEADER pTextSec = pe::GetSection(basePtr, 0x000000747865742E/*".text\0\0\0"*/);
		PIMAGE_SECTION_HEADER pPackerSec = pe::GetSection(basePtr, 0x0072656b6361702e/*".packer\0"*/);

		std::vector<PIMAGE_SECTION_HEADER> vsec = { pTextSec, pPackerSec };

		if (!pTextSec || !pPackerSec)
			return false;

		for (PIMAGE_SECTION_HEADER sechdr : vsec)
		{
			pfnSetProgressBarRange(0, 100, 10);

			std::uintptr_t secStart = (std::uintptr_t)basePtr + sechdr->PointerToRawData;
			std::uintptr_t secSize = sechdr->SizeOfRawData;

			std::string pattern = "?? 81 ?? ?? ?? ?? ?? ?? ?? ??";

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

			if (vpattern.size() != 10)
				return false;

			const std::uint8_t *cstart = (const std::uint8_t *)secStart;
			const std::uint8_t *cend = cstart + secSize;

			for (;;)
			{
				const std::uint8_t *res = std::search(cstart, cend, vpattern.begin(), vpattern.end(),
					[&wildcard](std::uint8_t v1, std::uint8_t v2)
				{
					return (v1 == v2 || v2 == wildcard);
				});

				if (res >= cend)
					break;

				std::uintptr_t found = reinterpret_cast<std::uintptr_t>(res);

				std::uint8_t opc_push = *(std::uint8_t*)(found);
				std::uint8_t opc_op = *(std::uint8_t*)(found + 2);
				std::uint8_t opc_pop = *(std::uint8_t*)(found + 7);
				std::uint8_t opc_branch = *(std::uint8_t*)(found + 8);

				if (std::find(lpush.begin(), lpush.end(), opc_push) != lpush.end()
					&& std::find(lop.begin(), lop.end(), opc_op) != lop.end()
					&& std::find(lpop.begin(), lpop.end(), opc_pop) != lpop.end()
					&& std::find(lbranch.begin(), lbranch.end(), opc_branch) != lbranch.end())
				{
					std::uint8_t size_val = *(std::uint8_t*)(found + 9);

					std::uint8_t opc_mov = *(std::uint8_t*)(found + size_val + 10);

					if (opc_mov == 0x8B)
					{
						std::uint8_t opc_branch2 = *(std::uint8_t*)(found + size_val + 18);

						if (opc_branch2 == 0x74)
							size_val += 10;
					}

					for (std::uintptr_t p = found; p < found + 10 + size_val; p++)
						*(std::uint8_t*)(p) = 0x90;
				}

				pfnProgressProgressBar(((double)((std::uintptr_t)res - (std::uintptr_t)secStart) / (double)((std::uintptr_t)cend)) * 1000);

				cstart = res + vpattern.size();
			}
		}

		return true;
	}
}