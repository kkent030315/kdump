#pragma once
#include <Windows.h>
#include <iostream>
#include <filesystem>

#include "format.hpp"
#include "win_utils.hpp"
#include "libmhyprot.h"

#define KDUMP_OUTPUT_FILE_PREFIX "kdump_"

namespace kdumper
{
	bool perform_dump(const std::string_view target_module_name)
	{
		if (target_module_name.empty())
		{
			printf("[!] module name must not be empty\n");
			return false;
		}

		printf("[>] finding %s module...\n", target_module_name.data());

		const uint64_t module_start_address = 
			win_utils::find_sysmodule_address(target_module_name);

		if (!module_start_address)
		{
			printf("[!] module %s address not found or invalid\n", target_module_name.data());
			return false;
		}

		printf("[+] module found at 0x%llX\n", module_start_address);
		printf("[>] snatching PE ...\n");

		const IMAGE_DOS_HEADER dos_header = 
			libmhyprot::read_kernel_memory<IMAGE_DOS_HEADER>(module_start_address);

		if (!dos_header.e_lfanew)
		{
			printf("[!] invalid dos header\n");
			return false;
		}

		const IMAGE_NT_HEADERS nt_header =
			libmhyprot::read_kernel_memory<IMAGE_NT_HEADERS>
			(module_start_address + dos_header.e_lfanew);

		if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
		{
			printf("[!] invalid dos header signature (0)\n");
			return false;
		}

		if (nt_header.Signature != IMAGE_NT_SIGNATURE)
		{
			printf("[!] invalid nt header signature (0)\n");
			return false;
		}

		const DWORD image_size = nt_header.OptionalHeader.SizeOfImage;

		if (!image_size)
		{
			printf("[!] invalid image size\n");
			return false;
		}

		printf("[+] image size: 0x%lX\n", image_size);
		printf("[<] snatched\n");

		BYTE* buffer = (BYTE*)(
			VirtualAlloc(
				NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
			));

		if (!buffer)
		{
			printf("[!] failed to allocate buffer\n");
			return false;
		}

		for (std::uint32_t page = 0x0;
			page < nt_header.OptionalHeader.SizeOfImage;
			page += 0x1000)
		{
			if (!libmhyprot::read_kernel_memory(module_start_address + page, buffer + page, 0x1000))
			{
				printf("[!] failed to read section[0x%lX]\n", page);
			}
		}

		PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)(buffer);

		if (p_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		{
			printf("[!] invalid dos header signature[0x%lX] (1)\n", p_dos_header->e_magic);
			VirtualFree(buffer, image_size, MEM_RELEASE);
			return false;
		}

		PIMAGE_NT_HEADERS p_nt_header = (PIMAGE_NT_HEADERS)(buffer + p_dos_header->e_lfanew);

		if (p_nt_header->Signature != IMAGE_NT_SIGNATURE)
		{
			printf("[!] invalid nt header signature[0x%lX] (1)\n", p_nt_header->Signature);
			VirtualFree(buffer, image_size, MEM_RELEASE);
			return false;
		}

		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(p_nt_header);

		printf("\n[>] fix sections...\n");

		for (WORD i = 0;
			i < p_nt_header->FileHeader.NumberOfSections; ++i,
			section++)
		{
			const std::string section_name((char*)section->Name);
			section->PointerToRawData = section->VirtualAddress;
			section->SizeOfRawData = section->Misc.VirtualSize;
			printf("[+] [%12s] 0x%06lX (0x%06lX)\n", section_name.c_str(), section->PointerToRawData, section->SizeOfRawData);
		}

		printf("[<] fixed\n\n");
		printf("[>] preparing output file...\n");

		const std::string output_path(std::string(KDUMP_OUTPUT_FILE_PREFIX) + target_module_name.data());

		if (std::filesystem::exists(output_path))
		{
			printf("[=] the output file %s is already exists. continue? [*y/n]\n", output_path.c_str());

			std::string operation;
			std::cin >> operation;

			if (operation.compare("n") == 0)
			{
				VirtualFree(buffer, image_size, MEM_RELEASE);
				printf("[#] dump canceled\n");
				return false;
			}

			if (!std::filesystem::remove(output_path))
			{
				VirtualFree(buffer, image_size, MEM_RELEASE);
				printf("[!] failed to remove existing file\n");
				return false;
			}
		}

		HANDLE file_handle = CreateFileA(
			output_path.c_str(),
			GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL
		);

		if (!CHECK_HANDLE(file_handle))
		{
			VirtualFree(buffer, image_size, MEM_RELEASE);
			printf("[!] failed to create file (0x%lX)\n", GetLastError());
			return false;
		}

		printf("\n[>] dumping results...\n");
		printf("[+] outout size: %s\n", format::convert_file_size(p_nt_header->OptionalHeader.SizeOfImage));

		if (!WriteFile(file_handle, buffer, p_nt_header->OptionalHeader.SizeOfImage, NULL, NULL))
		{
			VirtualFree(buffer, image_size, MEM_RELEASE);
			printf("[!] failed to write buffer to the output file (0x%lX)\n", GetLastError());
			return false;
		}

		printf("[+] dumped successfully\n\n");
		VirtualFree(buffer, image_size, MEM_RELEASE);

		return true;
	}
}