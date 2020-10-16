#include <Windows.h>
#include <iostream>

#include "libmhyprot.h"
#include "kdumper.hpp"

#pragma comment(lib, "libmhyprot.lib")

int main(int argc, const char** argv)
{
    printf("[=] kernel dumper using mhyprot vulnerable driver\n");

    if (argc < 2)
    {
        printf("[-] incorrect usage\n[-] usage: bin.exe [module name]");
        return -1;
    }

    if (!libmhyprot::mhyprot_init())
    {
        printf("[!] failed to init mhyprot exploit\n");
        libmhyprot::mhyprot_unload();
        return -1;
    }

    if (!kdumper::perform_dump(argv[1]))
    {
        libmhyprot::mhyprot_unload();
        printf("[!] dump failure\n");
        return -1;
    }

    libmhyprot::mhyprot_unload();

    printf("[<] done!\n");

    return 0;
}