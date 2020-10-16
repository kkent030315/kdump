#pragma once
#include <stdio.h> 
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

namespace format
{
	//
	// modified version of:
	// https://gist.github.com/dgoguerra/7194777
	// Credit: dgoguerra https://gist.github.com/dgoguerra
	// Thank you. :)
	//
	const char* convert_file_size(uint64_t bytes)
	{
		char* suffix[] = { (char*)"B", (char*)"KB", (char*)"MB", (char*)"GB", (char*)"TB" };
		char length = sizeof(suffix) / sizeof(suffix[0]);

		int i = 0;
		double dblBytes = bytes;

		if (bytes > 1024) {
			for (i = 0; (bytes / 1024) > 0 && i < length - 1; i++, bytes /= 1024)
				dblBytes = bytes / 1024.0;
		}

		static char output[200];
		sprintf_s(output, "%.02lf %s", dblBytes, suffix[i]);
		return output;
	}
}