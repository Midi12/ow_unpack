#include "Main.h"
#include "Decryptor_v1.h"

namespace decryptor_v1
{
	bool GatherData(const std::vector<std::uint8_t>& buffer, XorTable& xtable)
	{
		LPVOID basePtr = (LPVOID)buffer.data();

		if (!pe::IsValidDosHeader(basePtr))
			return false;

		if (!pe::IsValidNtHeaders(basePtr))
			return false;

		PIMAGE_NT_HEADERS pNtHeaders = pe::GetNtHeaders(basePtr);

		if (pNtHeaders == nullptr)
			return false;

		std::uintptr_t xtbl_address = LocateXorTable(buffer);
		xtable.SetAddress(xtbl_address);

		std::size_t xtbl_size = ComputeXorTableSize(buffer, helpers::RVAToFileOffset(pNtHeaders, xtable.GetAddress()));
		xtable.SetSize(xtbl_size);

		DumpXorTable(buffer, xtable, helpers::RVAToFileOffset(pNtHeaders, xtable.GetAddress()), xtable.GetSize());

		PIMAGE_SECTION_HEADER pPackerSec = pe::GetSection(basePtr, 0x0072656b6361702e/*".packer\0"*/);

		if (pPackerSec == nullptr)
			return false;

		std::uintptr_t packerSecStart = (std::uintptr_t)basePtr + pPackerSec->PointerToRawData;		
		std::uintptr_t packerSecSize = pPackerSec->SizeOfRawData;
		std::uintptr_t packerSecEnd = packerSecStart + packerSecSize;

		std::vector<std::uintptr_t> leaSearchRes;
		helpers::FindPattern(packerSecStart, packerSecSize, 0, "48 8D ?? ?? ?? ?? ??", leaSearchRes, nullptr);

		if (leaSearchRes.empty())
			return false;

		std::uintptr_t leaInst = 0x0;
		for (std::uintptr_t ptr : leaSearchRes)
		{
			std::uintptr_t a = xtable.GetAddress();
			std::uint32_t c = *(std::uint32_t*)(ptr + 3);
			std::uintptr_t b = helpers::RelativeToAbsolute(helpers::FileOffsetToRVA(pNtHeaders, ptr - (std::uintptr_t)basePtr), c, 7);
			if (a == b)
			{
				leaInst = ptr;
			}
		}

		std::uintptr_t imulStart = leaInst - 0x100;

		std::vector<std::uintptr_t> imulSearchRes;
		helpers::FindPattern(imulStart, leaInst - imulStart, 0, "?? 69 ?? ?? ?? ?? ??", imulSearchRes, [](std::uintptr_t p) -> std::uintptr_t
		{
			if (*(std::uint32_t*)(p + 3) > 0x0 && *(std::uint32_t*)(p + 3) < 0xFFF)
				return p;
			else
				return 0x0;
		});

		if (imulSearchRes.empty())
			return false;

		xtable.SetXModulo(*(std::uint32_t*)(*std::find_if(imulSearchRes.rbegin(), imulSearchRes.rend(), [](std::uintptr_t p) -> bool
		{
			return p != 0x0;
		}) + 3));
		xtable.SetIModulo(xtable.GetSize() / xtable.GetXModulo());

		return true;
	}

	std::uintptr_t LocateXorTable(const std::vector<std::uint8_t>& buffer)
	{
		std::uintptr_t address = 0x0;

		LPVOID ptr = (LPVOID)buffer.data();
		PIMAGE_SECTION_HEADER pDataSec = pe::GetSection(ptr, 0x000000617461642E/*".data\0\0\0"*/);

		if (pDataSec == nullptr)
			return 0x0;

		address = pDataSec->VirtualAddress;

		return address;
	}

	std::size_t ComputeXorTableSize(const std::vector<std::uint8_t>& buffer, std::uintptr_t xtbl_address)
	{
		LPVOID basePtr = (LPVOID)buffer.data();

		PIMAGE_NT_HEADERS pNtHeaders = pe::GetNtHeaders(basePtr);

		if (pNtHeaders == nullptr)
			return 0;

		std::size_t size = (std::size_t)(helpers::RVAToFileOffset(pNtHeaders, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) - xtbl_address);
		return size;
	}

	bool DumpXorTable(const std::vector<std::uint8_t>& buffer, XorTable& xtable, std::uintptr_t xtbl_address, std::size_t xtbl_size)
	{
		for (std::uintptr_t i = xtbl_address; i < xtbl_address + xtbl_size; i++)
			xtable.GetData().emplace_back(buffer[i]);

		return true;
	}

	bool DecryptHeader(const std::vector<std::uint8_t>& buffer, XorTable& xtable)
	{
		LPVOID basePtr = (LPVOID)buffer.data();

		PIMAGE_NT_HEADERS pNtHeaders = pe::GetNtHeaders(basePtr);
		if (!pNtHeaders)
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
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = importsSize;

		return true;
	}

	void DecryptDword(std::uintptr_t address, XorTable& xtable, int& idx)
	{
		std::uintptr_t ptr = address;

		do
		{
			ptr += 1;
			int offset = idx % xtable.GetXModulo();
			idx += 1;
			*(char *)(ptr - 1) = *(char *)(ptr - 1) ^ xtable.GetData()[offset];
		} while (idx < 4);
	}

	bool DecryptImportDescriptor(std::uintptr_t address, XorTable& xtable, int& idx)
	{
		int size = 0;
		std::uintptr_t ptr = address;

		do
		{
			ptr += 1;
			int offset = idx % xtable.GetXModulo();
			size += 1;
			idx += 1;
			*(char *)(ptr - 1) = *(char *)(ptr - 1) ^ xtable.GetData()[offset];
		} while (size < 0x14);

		return true;
	}

	bool DecryptString(std::uintptr_t address, XorTable& xtable, int& idx)
	{
		std::uintptr_t ptr = address;

		char first = *(char *)(ptr) ^ xtable.GetData()[idx % xtable.GetXModulo()];
		*(char *)(ptr) = first;

		char unxored = first;

		if (first = 0x00)
			return false;
		else
		{
			do
			{
				ptr += 1;
				idx += 1;
				unxored = *(char *)(ptr) ^ xtable.GetData()[idx % xtable.GetXModulo()];
				*(char *)(ptr) = unxored;
			} while (unxored != 0x00);
		}

		return true;
	}

	void DecryptQword(std::uintptr_t address, XorTable& xtable, int& idx)
	{
		std::uintptr_t ptr = address;
		int count = 0;

		do
		{
			*(char *)(ptr) = *(char *)(ptr) ^ xtable.GetData()[idx % xtable.GetXModulo()];
			idx += 1;
			ptr += 1;
			count += 1;
		} while (count < 8);
	}

	bool DecryptImportByName(std::uintptr_t address, XorTable& xtable, int& idx)
	{
		return DecryptString(address + 2, xtable, idx);
	}

	bool DecryptTextSection(const std::vector<std::uint8_t>& buffer, XorTable& xtable)
	{
		LPVOID basePtr = (LPVOID)buffer.data();

		PIMAGE_NT_HEADERS pNtHeaders = pe::GetNtHeaders(basePtr);
		if (!pNtHeaders)
			return nullptr;

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

	bool DecryptPage(std::uintptr_t phys_address, std::uintptr_t virt_address, XorTable& xtable, std::uintptr_t sectionVA)
	{
		std::uintptr_t ptr = phys_address;

		int idx = xtable.ComputeInitialIndex(virt_address & 0xFFFFFFFFFFFFF000, sectionVA);

		std::uintptr_t current_byte = 0x0;
		std::size_t page_size = 0x1000;

		while (current_byte < page_size)
		{
			*(std::uint8_t*)(ptr + current_byte) = *(std::uint8_t*)(ptr + current_byte) ^ xtable.GetData()[(xtable.GetXModulo() * idx) + current_byte % xtable.GetXModulo()];
			current_byte++;
		}

		return true;
	}

	bool RemoveObfuscationLayer(const std::vector<std::uint8_t>& buffer)
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

	bool RenameFakeTextSection(const std::vector<std::uint8_t>& buffer)
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
}