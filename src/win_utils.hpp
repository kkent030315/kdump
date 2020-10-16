#pragma once
#include <Windows.h>
#include <string>

#include "nt.hpp"

#define CHECK_HANDLE(x) (x && x != INVALID_HANDLE_VALUE)
#define MAX_ADDRESS ((ULONG_PTR)0x8000000000000000)

namespace win_utils
{
    uint64_t find_sysmodule_address(const std::string_view target_module_name)
    {
        const HMODULE module_handle = GetModuleHandle(TEXT("ntdll.dll"));

        if (!CHECK_HANDLE(module_handle))
        {
            return 0;
        }

        pNtQuerySystemInformation NtQuerySystemInformation =
            (pNtQuerySystemInformation)GetProcAddress(module_handle, "NtQuerySystemInformation");

        if (!NtQuerySystemInformation)
        {
            return 0;
        }

        NTSTATUS status;
        PVOID buffer;
        ULONG alloc_size = 0x10000;
        ULONG needed_size;

        do
        {
            buffer = calloc(1, alloc_size);

            if (!buffer)
            {
                return 0;
            }

            status = NtQuerySystemInformation(
                SystemModuleInformation,
                buffer,
                alloc_size,
                &needed_size
            );

            if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH)
            {
                free(buffer);
                return 0;
            }

            if (status == STATUS_INFO_LENGTH_MISMATCH)
            {
                free(buffer);
                buffer = NULL;
                alloc_size *= 2;
            }
        } while (status == STATUS_INFO_LENGTH_MISMATCH);

        if (!buffer)
        {
            return 0;
        }

        PSYSTEM_MODULE_INFORMATION module_information = (PSYSTEM_MODULE_INFORMATION)buffer;

        for (ULONG i = 0; i < module_information->Count; i++)
        {
            SYSTEM_MODULE_INFORMATION_ENTRY module_entry = module_information->Module[i];
            ULONG_PTR module_address = (ULONG_PTR)module_entry.DllBase;

            if (module_address < MAX_ADDRESS)
            {
                continue;
            }

            PCHAR module_name = module_entry.ImageName + module_entry.ModuleNameOffset;

            if (target_module_name.compare(module_name) == 0)
            {
                return module_address;
            }
        }

        free(buffer);

        return 0;
    }
}