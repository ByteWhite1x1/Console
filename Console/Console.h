#pragma once

namespace Console
{

	bool AttachViaProcessName(const char* processName);	
	bool ReadMemory(DWORD_PTR address, SIZE_T size, LPVOID buffer);
	DWORD64 ReadUInt64(DWORD_PTR address);	
	DWORD32 ReadUInt32(DWORD_PTR address);
	int ReadInt32(DWORD_PTR address);
	WORD ReadInt16(DWORD_PTR address);

}



