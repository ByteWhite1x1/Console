#pragma once

#include <windows.h>

class Helpers
{

public:

	static bool ReadMemory(DWORD_PTR address, SIZE_T size, LPVOID buffer);
	static bool WriteMemory(DWORD_PTR address, SIZE_T size, LPVOID buffer);
	static DWORD64 ReadUInt64(DWORD_PTR address);
	static int ReadInt32(DWORD_PTR address);
	static HANDLE hProcess;

};
