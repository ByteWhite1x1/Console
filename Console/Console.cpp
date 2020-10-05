// Console.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <windows.h>
#include <ctime>

#include <stdio.h>
#include <fstream>
#include <string>

#include <chrono>
#include <time.h>

#include <string.h> 
#include <stddef.h>

#include <clocale>
#include <set>
#include <tlhelp32.h>

#include <map>

#include "Console.h"

using namespace std; // 'std::' is no longer a requirement

#define PTR_ADD_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))

// Calculate the byte offset of a field in a structure of type type.

#define FIELD_OFFSET(type, field)    ((LONG)(LONG_PTR)&(((type *)0)->field))
#define UFIELD_OFFSET(type, field)    ((DWORD)(LONG_PTR)&(((type *)0)->field))

namespace Console
{

#include <io.h>
#define _O_TEXT 0x4000

	void OpenConsole() // With input and output
	{
		int hConHandle, m_nCRTIn = 0; HANDLE lStdHandle = 0; FILE *fp, *fr = 0;
		AllocConsole();
		lStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
		hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
		m_nCRTIn = _open_osfhandle((long)GetStdHandle(STD_INPUT_HANDLE), _O_TEXT);
		fp = _fdopen(hConHandle, "w");
		fr = _fdopen(m_nCRTIn, "r");
		*stdout = *fp;
		*stdin = *fr;
		HANDLE thread;
		SetConsoleTitleA("Console");
	}

	void SetColorConsole(int ForgC)
	{
		WORD wColor;
		HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		if (GetConsoleScreenBufferInfo(hStdOut, &csbi))
		{
			wColor = (csbi.wAttributes & 0xF0) + (ForgC & 0x0F);
			SetConsoleTextAttribute(hStdOut, wColor);
		}
		return;
	}

#define echo(x) \
Console::SetColorConsole(7); \
printf("%s \n", x); \
Console::SetColorConsole(10);	

}

char* StrToChar(const char *text, ...)
{

	static char result[1024];
	va_list va_alist;

	va_start(va_alist, text);
	vsnprintf(result, sizeof result, text, va_alist);
	va_end(va_alist);

	return result;
}

float ReadFloat(DWORD address)
{
	return *(float*)address;	
}

typedef int (WINAPI *pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
pNtQueryInformationProcess NtQueryInformationProcess;

bool DebugObjectCheck(HANDLE hProcess) // Did ont returned anything on Windows Pro 1909 with Windows debugger
{
	
	if (hProcess == NULL)
		return false;

	DWORD hDebugObject = 0;
	
	NTSTATUS status = NtQueryInformationProcess(hProcess,
		0x1f, // ProcessDebugObjectHandle
		&hDebugObject, 4, NULL);

	if (status != 0x0)
	{
		printf("%s\n", "NtQueryInformationProcess failed with status %d", status);
		return false;
	}			

	if (hDebugObject)
		return true;
	else
		return false;
}

// byte buffer[]

// In this way, text and key is passed as a pointer
char* XORDecrypt(BYTE text[], BYTE key[], int decLength)
{

	if (text == NULL || key == NULL)
		return 0;

	printf("decLength: %d \r\n", decLength);

	static char result[128] = "";
	memset(result, 0, sizeof(result));

	for (int i = 0; i < decLength; i++)
	{

		BYTE b = text[i];
		printf("%d \r\n", b);

		result[i] = (char)(text[i] ^ key[i % decLength]);

		/*
		if (b == NULL)
			MessageBox(NULL, "NULL", "", MB_OK);
		*/

		// printf("b: %x \r\n", b);

	}

	const int lastChar = decLength - 1;
	result[lastChar] = '\0';

	printf("result: %s \r\n", result);

	return result;

}

enum THREADINFOCLASS
{
	ThreadQuerySetWin32StartAddress = 9,
};

typedef NTSTATUS(__stdcall *pNtQueryInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG_PTR, ULONG_PTR*);

ULONG_PTR GetThreadStartAddress(HANDLE hThread)
{

	pNtQueryInformationThread NtQueryInformationThread = reinterpret_cast<pNtQueryInformationThread>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"));

	if (!NtQueryInformationThread)
		return 0;

	ULONG_PTR ulStartAddress = 0;
	NTSTATUS ret = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &ulStartAddress, sizeof(ULONG_PTR), nullptr);

	if (ret)
		return 0;

	return ulStartAddress;

}

void ListThreads()
{

	THREADENTRY32 threadEntry = { 0 };
	MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };

	HANDLE hTH32 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hTH32 == INVALID_HANDLE_VALUE)
		return;

	threadEntry.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(hTH32, &threadEntry))
	{

		do
		{

			if (threadEntry.th32OwnerProcessID == GetCurrentProcessId())
			{

				// var hThread = OpenThread(ThreadAccess.QUERY_INFORMATION, false, (uint)threadId);

				// HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, false, threadEntry.th32ThreadID);
				HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, false, threadEntry.th32ThreadID);

				auto startAddr = GetThreadStartAddress(hThread);

				// SuspendThread(hThread);
				// ResumeThread(hThread);

				CloseHandle(hThread);


				// LogFile::Write("Thread id: %04X %d start address: 0x%I64X", threadEntry.th32ThreadID, threadEntry.th32ThreadID, startAddr);

				// Misc::Echo("Thread id: %04X 0x%I64X", threadEntry.th32ThreadID, threadEntry.tpBasePri);

			}

		} while (Thread32Next(hTH32, &threadEntry));

	}

}

enum SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation
};

typedef struct _SECTION_BASIC_INFORMATION
{
	PVOID BaseAddress;
	ULONG AllocationAttributes;
	LARGE_INTEGER MaximumSize;
} SECTION_BASIC_INFORMATION, *PSECTION_BASIC_INFORMATION;

typedef LONG(NTAPI *lpfNtQuerySection)(
		IN HANDLE               SectionHandle,
		IN SECTION_INFORMATION_CLASS InformationClass,
		OUT PVOID               InformationBuffer,
		IN ULONG                InformationBufferSize,
		OUT PULONG              ResultLength);

lpfNtQuerySection NtQuerySection;

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
	WORD wIndex = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;

	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;

	for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
	{
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
	}

	return 0;
}

void WalkExports(LPCTSTR FileName)
{

	HMODULE hModule = LoadLibraryA("ntdll.dll");

	if (hModule == NULL)
	{
		return;
	}

	HANDLE hFile = 0;
	HANDLE hFileMap = 0;
	BYTE *lpFileMap = 0;
	IMAGE_DOS_HEADER *ImageDosHeader = 0;
	IMAGE_NT_HEADERS *ImageNtHeader = 0;
	DWORD i = 0;
	DWORD ExportDirectoryRVA = 0;
	IMAGE_EXPORT_DIRECTORY *ImageExportDirectory = 0;
	DWORD NumberOfNames = 0;
	DWORD *ArrayOfNames = 0;
	DWORD *ArrayOfAddresses = 0;
	DWORD *ArrayOfNameOrdinals = 0;
	DWORD Base = 0;

	hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, GetFileAttributes(FileName), NULL);

	if (hFile != INVALID_HANDLE_VALUE)
	{

		hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, NULL, NULL, NULL);

		if (hFileMap != NULL)
		{

			lpFileMap = (BYTE*)MapViewOfFile(hFileMap, FILE_MAP_READ, NULL, NULL, NULL);

			if (lpFileMap != NULL)
			{

				// lpfNtQuerySection NtQuerySection;

				NtQuerySection = (lpfNtQuerySection)GetProcAddress(hModule, "NtQuerySection");

				if (NtQuerySection == NULL)
					return;

				SECTION_BASIC_INFORMATION sbi = { 0 };
			
				ULONG pLength = 0;
				NTSTATUS stat = NtQuerySection(lpFileMap, SectionBasicInformation, &sbi, sizeof(sbi), &pLength);

				if (stat >= 0)
				{
					printf("%s\n", "BLA");
				}
				else
				{
					printf("%s %d\n", "Status:", stat);
				}				

				ImageDosHeader = (IMAGE_DOS_HEADER*)lpFileMap;

				if (ImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
				{

					ImageNtHeader = (IMAGE_NT_HEADERS*)(lpFileMap + ImageDosHeader->e_lfanew);

					if (ImageNtHeader->Signature == IMAGE_NT_SIGNATURE)
					{

						ExportDirectoryRVA = ImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

						printf("%s 0x%I64X \n", "ExportDirectoryRVA", ExportDirectoryRVA);

						ImageExportDirectory = (IMAGE_EXPORT_DIRECTORY*)(Rva2Offset(ExportDirectoryRVA, (UINT_PTR)lpFileMap) + lpFileMap);
						NumberOfNames = ImageExportDirectory->NumberOfNames;
						ArrayOfAddresses = (DWORD*)(Rva2Offset(ImageExportDirectory->AddressOfFunctions, (UINT_PTR)lpFileMap) + lpFileMap);
						ArrayOfNames = (DWORD*)(Rva2Offset(ImageExportDirectory->AddressOfNames, (UINT_PTR)lpFileMap) + lpFileMap);
						ArrayOfNameOrdinals = (DWORD*)(Rva2Offset(ImageExportDirectory->AddressOfNameOrdinals, (UINT_PTR)lpFileMap) + lpFileMap);
						Base = ImageExportDirectory->Base;
						printf("Number   RVA      Name\n");

						for (i = 0; i < NumberOfNames; i++)
						{
							printf("%04X:    %08X %s\n", i + Base, ArrayOfAddresses[i], (Rva2Offset((DWORD)ArrayOfNames[i], (UINT_PTR)lpFileMap) + lpFileMap));

						}

					}
					else
					{
						printf("%s has no PE signature.\n", FileName);
					}

				}
				else
				{
					printf("%s has no DOS signature.\n", FileName);
				}
				UnmapViewOfFile(lpFileMap); //Destroy mapped view of file.   
			}
			else
			{
				printf("Failed to create mapped view of file.\n");
			}
			CloseHandle(hFileMap); //Destroy file map object.   
		}
		else
		{
			printf("Failed to create file mapping object.\n");
		}
		CloseHandle(hFile); //Destroy file handle.   
	}
	else
	{
		printf("Failed to open file for reading.\n");
	}
}

HANDLE hProcess;
DWORD pid;

bool Console::AttachViaProcessName(const char* processName)
{

	PROCESSENTRY32 processEntry = { 0 };
	MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };

	HANDLE hTH32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hTH32 == INVALID_HANDLE_VALUE)
		return FALSE;

	processEntry.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hTH32, &processEntry))
	{

		do
		{

			if (_stricmp(processEntry.szExeFile, processName) == 0)
			{

				pid = processEntry.th32ProcessID;
				CloseHandle(hTH32);

				break;

			}

		} while (Process32Next(hTH32, &processEntry));

	}

	if (pid == 0)
	{		
		return FALSE;
	}

	hProcess = OpenProcess(0x1FFFFF, FALSE, pid);

	if (hProcess == NULL)
	{		
		return FALSE;
	}

	return TRUE;

}

void MonitorMemoryAllocations()
{

	if (hProcess == NULL)
		return;

	bool monitorAllocationsFirstInit = true;

	std::map<LPVOID, DWORD> allocatedRegions;

	MEMORY_BASIC_INFORMATION mbi = { 0 };

	SYSTEM_INFO si;
	GetSystemInfo(&si);
	
	while (true)
	{

		DWORD64 procMinAddress = (DWORD64)si.lpMinimumApplicationAddress;
		DWORD64 procMaxAddress = (DWORD64)si.lpMaximumApplicationAddress;

		while (procMinAddress < procMaxAddress)
		{

			auto ret = VirtualQueryEx(hProcess, (LPVOID)procMinAddress, &mbi, sizeof(mbi));

			if (ret == 0)
			{
				printf("%s %d \r\n", "GetLastError()", GetLastError());
				return;
			}

			if (mbi.State == MEM_COMMIT)
			{

				if (mbi.AllocationProtect == PAGE_READONLY || mbi.AllocationProtect == PAGE_NOCACHE || mbi.AllocationProtect == PAGE_NOACCESS)
				{
					goto endloop;
				}

				if (!monitorAllocationsFirstInit)
				{

					if (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE || mbi.AllocationProtect == PAGE_EXECUTE_READ ||
						mbi.AllocationProtect == PAGE_EXECUTE_WRITECOPY || mbi.AllocationProtect == PAGE_READWRITE)
					{

						// if (!allocatedRegions[mbi.BaseAddress] && mbi.RegionSize == 0x1000)
						if (!allocatedRegions[mbi.BaseAddress])
						{

							allocatedRegions[mbi.BaseAddress] = mbi.AllocationProtect;
							printf("Memory allocation: 0x%I64X dwSize: 0x%I64X flProtect: 0x%08X \r\n", (DWORD64)mbi.BaseAddress, (DWORD64)mbi.RegionSize, mbi.AllocationProtect);

						}

					}

					if (allocatedRegions[mbi.BaseAddress])
					{

						DWORD allocationProtect = allocatedRegions[mbi.BaseAddress];

						if (mbi.AllocationProtect != allocationProtect)
						{
							allocatedRegions[mbi.BaseAddress] = mbi.AllocationProtect;
							printf("Allocated base address 0x%I64X dwSize: 0x%I64X allocationProtect 0x%08X => 0x%08X \r\n", (DWORD64)mbi.BaseAddress, (DWORD64)mbi.RegionSize, allocationProtect, mbi.AllocationProtect);
						}

					}

				}
				else
				{
					allocatedRegions[mbi.BaseAddress] = mbi.AllocationProtect;
				}

			}

		endloop:

			procMinAddress += mbi.RegionSize;

		}

		if (monitorAllocationsFirstInit)
			monitorAllocationsFirstInit = false;

		

	}

	CloseHandle(hProcess);

}

DWORD64 Console::ReadUInt64(DWORD_PTR address)
{

	BYTE *buffer = new BYTE[8];
	Console::ReadMemory(address, 8, buffer);

	DWORD_PTR value = *reinterpret_cast<DWORD_PTR*>(buffer);
	delete[] buffer;

	return value;

}

int Console::ReadInt32(DWORD_PTR address)
{

	BYTE *buffer = new BYTE[4];
	Console::ReadMemory(address, 4, buffer);

	int value = *reinterpret_cast<int*>(buffer);
	delete[] buffer;

	return value;

}

DWORD32 Console::ReadUInt32(DWORD_PTR address)
{

	BYTE *buffer = new BYTE[4];
	Console::ReadMemory(address, 4, buffer);

	DWORD32 value = *reinterpret_cast<DWORD32*>(buffer);
	delete[] buffer;

	return value;

}

WORD Console::ReadInt16(DWORD_PTR address)
{

	BYTE *buffer = new BYTE[2];
	Console::ReadMemory(address, 2, buffer);

	WORD value = *reinterpret_cast<WORD*>(buffer);
	delete[] buffer;

	return value;

}

bool Console::ReadMemory(DWORD_PTR address, SIZE_T size, LPVOID lpBuffer)
{

	SIZE_T lpNumberOfBytesRead = 0;

	if (!ReadProcessMemory(hProcess, (LPVOID)address, lpBuffer, size, &lpNumberOfBytesRead))
		return FALSE;

	return TRUE;

}

int main()
{
    
	Console::OpenConsole();
	echo("CONSOLE");			

	CONTEXT ctx = { 0 };	

	// CONTEXT *pCTX = ctx;

	cout << "Struct CONTEXT Total Size: " << sizeof(CONTEXT) << endl << endl;

	cout << "Data Types:" << endl;
	cout << "-----------" << endl;
	cout << "DWORD64: " << sizeof(DWORD64) << " bytes" << endl;
	cout << "DWORD: " << sizeof(DWORD) << " bytes" << endl;
	cout << "WORD: " << sizeof(WORD) << " bytes" << endl;
	cout << "ULONGLONG: " << sizeof(ULONGLONG) << " bytes" << endl;
	cout << "LONGLONG: " << sizeof(LONGLONG) << " bytes" << endl;
	cout << "M128A: " << sizeof(M128A) << " bytes" << endl;
	cout << "XMM_SAVE_AREA32: " << sizeof(XMM_SAVE_AREA32) << " bytes" << endl;

	/*
	int size = sizeof(ctx);
	printf("\n\n%d", size);

	// printf("offsetof(struct foo,a) is %d\n", (int)offsetof(struct ctx, ctx.Rax));

	// int offset = offsetof(struct CONTEXT, LastExceptionFromRip);	

	// int offset = FIELD_OFFSET(CONTEXT, Xmm15);

	int offset = FIELD_OFFSET(IMAGE_DOS_HEADER, e_lfanew);	
	printf("\n\n offset: %d", offset);
	*/

	// std::setlocale(LC_ALL, "en_US.UTF-8");	
	// WalkExports("C:\\Windows\\System32\\ntdll.dll");
		
	if (!Console::AttachViaProcessName("bfv.exe"))
		return 0;

	// MonitorMemoryAllocations();

	// 

	hProcess = OpenProcess(0x1FFFFF, FALSE, pid);

	if (hProcess == NULL)
	{
		return FALSE;
	}

	DWORD64 baseAddress = 0x7FFC7C340000;

	auto m_DosSig = Console::ReadInt16((ULONG_PTR)baseAddress + 0x0);
	
	// int m_DosSig = *(int*)((ULONG_PTR)it->first + 0x3C);

	auto pNtHdrs = Console::ReadInt32((ULONG_PTR)baseAddress + 0x3C);	

	auto m_NTSig = Console::ReadInt32((ULONG_PTR)baseAddress + pNtHdrs);


	if (m_DosSig == IMAGE_DOS_SIGNATURE && m_NTSig == IMAGE_NT_SIGNATURE)
	{

		printf("PE header \r\n");		

	}

	std::cin.get();

	return 0;

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
