
#include "Helpers.h"

bool Helpers::ReadMemory(DWORD_PTR address, SIZE_T size, LPVOID lpBuffer)
{

	/*
	ReadProcessMemory(
	_In_ HANDLE hProcess,
	_In_ LPCVOID lpBaseAddress,
	_Out_writes_bytes_to_(nSize,*lpNumberOfBytesRead) LPVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T* lpNumberOfBytesRead
	);
	*/

	SIZE_T lpNumberOfBytesRead = 0;

	if (!hProcess)
	{
		return FALSE;
	}

	if (!ReadProcessMemory(hProcess, (LPVOID)address, lpBuffer, size, &lpNumberOfBytesRead))
		return FALSE;

	return TRUE;

}

bool Helpers::WriteMemory(DWORD_PTR address, SIZE_T size, LPVOID buffer)
{

	SIZE_T lpNumberOfBytesWritten = 0;

	if (!hProcess)
	{
		return false;
	}

	return (WriteProcessMemory(hProcess, (LPVOID)address, buffer, size, &lpNumberOfBytesWritten) != FALSE);

}

DWORD64 Helpers::ReadUInt64(DWORD_PTR address)
{

	BYTE *buffer = new BYTE[8];
	Helpers::ReadMemory(address, 8, buffer);

	DWORD_PTR value = *reinterpret_cast<DWORD_PTR*>(buffer);
	delete[] buffer;

	return value;

}

INT Helpers::ReadInt32(DWORD_PTR address)
{

	BYTE *buffer = new BYTE[4];
	Helpers::ReadMemory(address, 4, buffer);

	int value = *reinterpret_cast<int*>(buffer);
	delete[] buffer;

	return value;

}
