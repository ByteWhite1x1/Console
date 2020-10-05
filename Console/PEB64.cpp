#include <windows.h>
#include "PEB64.h"
#include <tlhelp32.h>
// #include "Init.h"
#include "Helpers.h"
#include <cstdlib>
#include <cwchar>

#define __STDC_WANT_LIB_EXT1__ 1

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PTR_ADD_OFFSET(pointer, offset) ((PVOID)((ULONG_PTR)(pointer) + (ULONG_PTR)(offset)))


HANDLE Helpers::hProcess;

bool PEB64::Attach(const char* processName)
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
		printf("%s\n", "Could not find a process by that name.");
		return FALSE;
	}

	hProcess = OpenProcess(0x1FFFFF, FALSE, pid);

	if (hProcess == NULL)
	{		
		printf("%s\n", "Failed to initialize a handle.");
		return FALSE;
	}

	return TRUE;

}

void PEB64::GetProcessPEB()
{

	/*
	if (!AdjustPrivilege("SE_DEBUG_NAME"))
	{
		// int msgboxID = MessageBox(NULL, (LPCWSTR)L"SE_DEBUG_NAME was not set.", MB_OK, NULL);
	}
	*/

	hModule = LoadLibrary("ntdll.dll");
	// hModule = GetModuleHandleA("ntdll.dll");

	if (hModule == NULL)
	{
		int msgboxID = MessageBox(NULL, "hModule is NULL", MB_OK, NULL);
	}

	NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");

	if (NtQueryInformationProcess == NULL)
	{
		int msgboxID = MessageBox(NULL, "!NtQueryInformationProcess ...", MB_OK, NULL);
	}

	status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &dwLength);

	if (status != 0x0)
	{		
		printf("%s\n", "NtQueryInformationProcess failed with status %d", status);
	}

	Helpers::hProcess = hProcess;

	DWORD64 m_ProcessParameters = Helpers::ReadUInt64((DWORD64)pbi.PebBaseAddress + 0x0020);
	m_EnvironmentVariables = Helpers::ReadUInt64(m_ProcessParameters + 0x0080); // The start of environment variables block	

#pragma region ToUInt64
#pragma endregion ToUInt64

	// printf("\n\n %s 0x%I64X", "m_EnvironmentVariables: ", (void*)m_EnvironmentVariables);
	printf("\n\n%s 0x%I64X \n", "m_EnvironmentVariables: ", m_EnvironmentVariables);

	// Init::MsgBox("PEB address: 0x%I64X m_EnvironmentVariables: 0x%I64X", pbi.PebBaseAddress, m_EnvironmentVariables);

}

// https://docs.microsoft.com/en-us/windows/win32/procthread/environment-variables

DWORD64 PEB64::m_EnvironmentVariables;

// https://docs.microsoft.com/en-us/windows/win32/procthread/environment-variables

void PEB64::GetEnvironmentVariables()
{

	// Init::MsgBox("PEB address: 0x%I64X m_EnvironmentVariables: 0x%I64X", pbi.PebBaseAddress, m_EnvironmentVariables);
	// Init::Log("PEB address: 0x%I64X m_EnvironmentVariables: 0x%I64X", pbi.PebBaseAddress, m_EnvironmentVariables);	

	PVOID environmentAddress = (PVOID)PEB64::m_EnvironmentVariables;

	NtReadVirtualMemory = (lpfNtReadVirtualMemory)GetProcAddress(hModule, "NtReadVirtualMemory");

	if (NtReadVirtualMemory == NULL)
	{
		int msgboxID = MessageBox(NULL, "!NtReadVirtualMemory ...", MB_OK, NULL);
	}

	DWORD64 m_ProcessParameters = Helpers::ReadUInt64((DWORD64)pbi.PebBaseAddress + 0x0020);
	int environmentSize = Helpers::ReadInt32(m_ProcessParameters + 0x03F0);

	// int envSize = environmentSize / sizeof(WCHAR);
	// Init::MsgBox("%d", environmentSize);

	int envSize = environmentSize;
	printf("%s %d \n", "Environment size: ", envSize);	

	// wchar_t* pBuffEnvString = new WCHAR[envSize];
	// PWSTR* pBuffEnvString = new PWSTR[envSize];

	// memset(pBuffEnvString, 0, sizeof(WCHAR) * environmentSize); // Useless

	BYTE* pBytes = new BYTE[envSize];	
	Helpers::ReadMemory(PEB64::m_EnvironmentVariables + 0x0010, envSize, pBytes);

	// WCHAR tmp[2];
	// wmemcpy(tmp, pBuffEnvString, 1);

	// wcscpy_s(tmp, 1, pBuffEnvString);
	
	// wprintf(L"%S\n", wc);

	// printf("%ls\n", wc);
	
	// printf("%ls", pBuffEnvString[0]);
	
	// char* str = (char*)(*(DWORD_PTR*)m_EnvironmentVariables + 0x0010); Works internally


	// printf("%d \n", sizeof(pBuffer[0]));
	// return;

	// printf("%c", (char)pBuffer[0]);	

	const int buffLength = 1024;

	char chars[buffLength];
	char* pBuff = chars;

	int index = 0;
	ENVIRONMENT_VARIABLE variable;

	variable.Name.Length = 0;
	variable.Value.Length = 0;

	__try
	{

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}


	// The environment variables are made available to main() as the envp argument - a null terminated array of strings
	// https://www.geeksforgeeks.org/c-program-print-environment-variables/

	for (int i = 0; i < envSize; i++) {
		
		BYTE b = pBytes[i];

		char ch = (char)b;

		if (!(b >= 0 && b < 128)) // Only ASCII
		{
			continue;
		}

		if (b != 0)
		{

			pBuff[index] = ch;
			index++;			
			
		}				
		else
		{


			if (i + 1 <= envSize)
			{

				byte nextByte = pBytes[i + 1];

				if (nextByte == 0)
				{					


					CHAR* pName = variable.Name.Buffer;

					int tmpIndex = 0;

					for (int j = 0; j < index; j++)
					{

						char c = pBuff[j];

						if (c != '=')
						{
							pName[j] = c;
							tmpIndex++;
						}
						else
						{							
							break;
						}						

					}

					variable.Name.Length = index;
					tmpIndex++;

					CHAR* pValue = variable.Value.Buffer;
					
					int l = 0;

					for (int k = tmpIndex; k < index; k++)
					{

						char c = pBuff[k];

						pValue[l] = c;
						l++;

					}

					// printf("%s %s\n", pName, pValue);
					
					if (strcmp(pName, "DEBUG_ADDRESS") == 0)
					{

						DWORD64 hexValue = strtoull(pValue, 0, 16);

						// addressToDebug = hexValue;
						// Init::MsgBox("0x%I64X", hexValue);

						printf("%s 0x%I64X\n", "DEBUG_ADDRESS:", hexValue);
						// int msgboxID = MessageBox(NULL, "ONKOT LOMILLA ...", MB_OK, NULL);

					}

					if (strcmp(pName, "DEBUG_TYPE") == 0)
					{

						if (strcmp(pValue, "Read") == 0)
						{

						}
						else if (strcmp(pValue, "Write") == 0)
						{

						}
						else if (strcmp(pValue, "Execute") == 0)
						{

						}
						else
						{
							int msgboxID = MessageBox(NULL, "Unknown debug type ...", MB_OK, NULL);
						}

						printf("%s %s\n", "DEBUG_TYPE:", pValue);

					}



					index = 0;
					memset(pBuff, '\0', sizeof(CHAR) * buffLength);		
					memset(variable.Name.Buffer, '\0', sizeof(CHAR) * buffLength);
					memset(variable.Value.Buffer, '\0', sizeof(CHAR) * buffLength);

					i++;

				}

			}			

		}	

	}

}