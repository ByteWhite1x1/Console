#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include "Init.h"
#include "Helpers.h"
#include "PEB64.h"

#include <stdio.h>
#include <fstream>
#include <ctime>
#include <string>

#include <tlhelp32.h>
#include <malloc.h>
#include <chrono>

// https://docs.microsoft.com/en-us/windows/win32/sync/using-semaphore-objects
// https://docs.microsoft.com/en-us/dotnet/standard/io/memory-mapped-files
// https://caligari.dartmouth.edu/doc/ibmcxx/en_US/doc/libref/tasks/tumemex2.htm

using namespace std; // 'std::' is no longer a requirement

#define MAX_SEM_COUNT 10
HANDLE hSemaphore;

/* Allocate a 4k block in remote process */
const int noBlocks = 4;
const int memToAlloc = 1024;

// DWORD_PTR *pointer = NULL;
void* ptrToSHM = NULL;

HANDLE Helpers::hProcess; // // A declaration of the variable

// __debugType

char szLogFile[MAX_PATH];
char szBaseDir[MAX_PATH];

volatile bool debug = true;

int restoreBreakPointForThreadId = 0;
DWORD64 restoreBreakPointTicks = 0;

DWORD exceptionCount = 0;

// https://gist.github.com/mattwarren/6e4b3c13f24ef66fe76b0492a5ed006a


long WINAPI VectoredExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo)
{

	EXCEPTION_RECORD* pExc = pExceptionInfo->ExceptionRecord;

	PCONTEXT ctx = pExceptionInfo->ContextRecord;

	DWORD exceptionCode = pExc->ExceptionCode;

	// void* exceptionAddress = (void*)pExc->ExceptionAddress;
	PVOID exceptionAddress = pExc->ExceptionAddress;

	if (exceptionCode == EXCEPTION_SINGLE_STEP) // A HWBP seems to always be a single step
	{

		// int msgboxID = MessageBox(NULL, (LPCWSTR)L"EXCEPTION_SINGLE_STEP", MB_OK, NULL);

		/*
		CONTEXT ctx = { 0 };
		int size = sizeof(ctx); // 1232
		*/

		// Init::MsgBox("%d", size);

		// The values are set directly into the exception record in a VEH. GetThreadContext() and SetThreadContext() does not work in a VEH handler.		

		// Do whatever with the context ...

		// MsgBox("exceptionAddress 0x%I64X", ctx->Rip);
		// MsgBox("DR0 0x%I64X", ctx->Dr0);

		// If the "DebugType" is Execute, remove the HWBP and restore right after removal			

		/*
		Init::DebugType d = Init::GetDebugType();

		// Init::DebugType d = Init::debugType;
		MsgBox("d %d", d);
		*/

		bool wasAHardwareBreakPoint = false;

		if ((ctx->Dr6 & (1 << (0 * 2))) == 1)
		{

			// DR0
			wasAHardwareBreakPoint = true;

			if (debug)
				Init::Log("%s", "Caused by DR0 ...");

		}
		else if ((ctx->Dr6 & (1 << (1 * 2))) == 1)
		{

			// DR1
			wasAHardwareBreakPoint = true;

			if (debug)
				Init::Log("%s", "Caused by DR1 ...");

		}
		else if ((ctx->Dr6 & (1 << (2 * 2))) == 1)
		{

			// DR2
			wasAHardwareBreakPoint = true;

			if (debug)
				Init::Log("%s", "Caused by DR2 ...");

		}
		else if ((ctx->Dr6 & (1 << (3 * 2))) == 1)
		{

			// DR3
			wasAHardwareBreakPoint = true;

			if (debug)
				Init::Log("%s", "Caused by DR3 ...");

		}
		else
		{

			if (debug)
				Init::Log("%s", "Not caused by a debug register ...");

		}

		if (wasAHardwareBreakPoint)
		{

			memcpy(ptrToSHM, ctx, 1232); // Copy the context to our "SHM" address

			if (PEB64::debugType == Execute)
			{

				// Init::MsgBox("Address: 0x%I64X", ptrToSHM);

				ctx->Dr0 = 0;
				ctx->Dr6 = 0;
				ctx->Dr7 = 0;

				/*
				int threadId = GetCurrentThreadId(); // The id of the thread that throw the exception

				auto ticks = GetTickCount64();
				// MsgBox("ticks %d", ticks);

				restoreBreakPointForThreadId = threadId;
				restoreBreakPointTicks = ticks + 50;
				*/

			}

			if (debug)
				Init::Log("exceptionCode: 0x%I64X exceptionAddress: 0x%I64X exceptionCount: %d", exceptionCode, exceptionAddress, exceptionCount);

			exceptionCount++;

			/// ...

			/*
			while (*ptr == 0xA)
			{
				Sleep(1);
			}
			*/

			// After the semaphore has been released, the other thread will restore the breakpoint

			if (!ReleaseSemaphore(hSemaphore, 1, NULL))
			{
				// printf("ReleaseSemaphore error: %d\n", GetLastError());
				// int msgboxID = MessageBox(NULL, (LPCWSTR)L"ReleaseSemaphore error", MB_OK, NULL);
				Init::Log("%s", "ReleaseSemaphore error ...");
			}

		}

		return EXCEPTION_CONTINUE_EXECUTION;

	}
	else if (exceptionCode == EXCEPTION_BREAKPOINT) // 0xCC INT3
	{
		int msgboxID = MessageBox(NULL, "EXCEPTION_BREAKPOINT", MB_OK, NULL);
		// pExceptionInfo->ContextRecord->EFlags |= 0x00000100;
	}
	else if (exceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		// int msgboxID = MessageBox(NULL, (LPCWSTR)L"EXCEPTION_ACCESS_VIOLATION", MB_OK, NULL);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else
	{

	}

	/*
	DWORD64 exceptionAddr = reinterpret_cast<DWORD64>(exceptionAddress);
	*/

	if (debug)
		Init::Log("exceptionCode: 0x%I64X exceptionAddress: 0x%I64X", exceptionCode, exceptionAddress);

	int msgboxID = MessageBox(NULL, "ONKO MIE!?", MB_OK, NULL);

	return EXCEPTION_CONTINUE_SEARCH;

}

// #define OFFSET_HWBP 0xA6D901A000 + 2;
// const DWORD64 OFFSET_HWBP = 0x147CFB247;



int Init::InitVEH()
{

	// sprintf_s(szLogFile, "%sdebug.txt", szBaseDir);

	sprintf_s(szLogFile, "%sC:\\C++\\VEHDebug\\x64\\Release\\debug.txt", szBaseDir);

	std::ofstream fout;
	fout.open(szLogFile, std::ios::trunc); // Truncate to zero length
	fout.close();

	SYSTEM_INFO sysInfo;
	GetNativeSystemInfo(&sysInfo);

	// MsgBox("Address: 0x%I64X", sysInfo.dwAllocationGranularity);

	// pointer = (void*)malloc(memToAlloc);
	// void* calloc(size_t num, size_t size);

	ptrToSHM = (void*)calloc(noBlocks, memToAlloc);

	if (ptrToSHM == NULL)
	{
		int msgboxID = MessageBox(NULL, "The memory could not be allocated.", MB_OK, NULL);
		return -1;
	}

	/*
	for (int i = 0; i < memToAlloc; i++) {
		pointer[i] = 0;
	}
	*/

	Init::Log("SHM address: 0x%I64X", ptrToSHM);
	MsgBox("SHM: 0x%I64X", ptrToSHM);

	// unsigned long to hex string
	char hex[16];
	sprintf(hex, "0x%I64X", ptrToSHM);


	SetEnvironmentVariable("SHM_ADDRESS", hex);

	// s << "0x" << std::hex << ptrToSHM;

	// int msgboxID = MessageBox(NULL, (LPCWSTR)L"OK", MB_OK, NULL);

	// BYTE value = *(reinterpret_cast<unsigned char*>(pointer));

	// https://www.geeksforgeeks.org/reinterpret_cast-in-c-type-casting-operators/	

	int* value = reinterpret_cast<int*>(ptrToSHM); // The value at that address as an "int" value
	*value = 11; // Set the value to

	int* _value = reinterpret_cast<int*>((DWORD_PTR)ptrToSHM + 1232 + 8);
	*_value = 10;

	// int msgboxID = MessageBox(NULL, (LPCWSTR)L"ONKO MIE!?", MB_OK, NULL);

	// free(ptrToSHM);

	if (Helpers::hProcess == NULL)
	{

		/*
		auto address = *(DWORD64**)(0x0); // Deref a static pointer.
		MsgBox("Address: 0x%I64X", address);
		*/

		int currentProcId = GetCurrentProcessId();
		Helpers::hProcess = OpenProcess(0x1FFFFF, FALSE, currentProcId);

	}

	/*
	BYTE bytesToWrite[1];
	bytesToWrite[0] = 0xC3;

	Helpers::WriteMemory(0x147CFB180, 1, bytesToWrite);
	*/

	/*
	BYTE *buffer = new BYTE[1];
	Helpers::ReadMemory(0x147CFB180, 1, buffer);

	if (buffer[0] == 0x48)
		int msgboxID = MessageBox(NULL, (LPCWSTR)L"ONKO MIE!?", MB_OK, NULL);

	delete[] buffer;
	*/

	// CloseHandle(Helpers::hProcess);

	// Init::Log("%s", "ONKO MIE!?");				

	// MsgBox("Address: 0x%I64X", this->address);

	// Init::Log("Address: 0x%I64X", address);

	/*
	if (Init::_debugType == 3)
		int msgboxID = MessageBox(NULL, (LPCWSTR)L"ONKO MIE!?", MB_OK, NULL);
	*/

	/*
	int size = sizeof(cp);

	CString str;
	str.Format(_T("%d"), size);


	int msgboxID = MessageBox(NULL, str, MB_OK, NULL);
	*/

	hSemaphore = CreateSemaphore(NULL, 0, MAX_SEM_COUNT, NULL);

	if (hSemaphore == NULL)
	{
		int msgboxID = MessageBox(NULL, "The semaphore was not initialized.", MB_OK, NULL);
		return -1;
	}

	volatile bool shouldStop;
	shouldStop = FALSE;

	// Set HWBP's ...
	// https://www.codereversing.com/blog/archives/76 not on my thread though
	// http://bytepointer.com/resources/pietrek_vectored_exception_handling_figures.htm#fig2	

	// int msgboxID = MessageBox(NULL, (LPCWSTR)L"ONKO MIE!?", MB_OK, NULL);

	// Add the handler only once
	if (this->hVEH == NULL)
	{

		this->hVEH = AddVectoredExceptionHandler(1, &VectoredExceptionHandler); // https://docs.microsoft.com/en-us/archive/msdn-magazine/2001/september/under-the-hood-new-vectored-exception-handling-in-windows-xp

		if (debug)
			Init::Log("%s", "Added a VEH ...");

	}

	SetBreakPoint(0);

	while (!shouldStop)
	{

		/*
		__try
		{
			RaiseException(EXCEPTION_SINGLE_STEP, 0, 0, NULL);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{

		}
		*/

		if (shouldStop == TRUE)
		{
			// set "haveStopped" to TRUE ...

			if (this->hVEH != NULL)
			{
				RemoveVectoredExceptionHandler(this->hVEH);
			}

			CloseHandle(hSemaphore);
			break;

		}

		DWORD dwWaitResult = WaitForSingleObject(hSemaphore, -1); // Wait until the semaphore is signaled 

		// The semaphore object was signaled.
		if (dwWaitResult == WAIT_OBJECT_0)
		{

			/*
			auto ticks = GetTickCount64();

			if (restoreBreakPointTicks != 0)
			{

				if (ticks >= restoreBreakPointTicks)
				{

					SetBreakPoint(restoreBreakPointForThreadId);

					restoreBreakPointForThreadId = 0;
					restoreBreakPointTicks = 0;

					if (debug)
						Log("Restored HWBP for thread %d", restoreBreakPointForThreadId);

				}

			}
			*/

			SetBreakPoint(restoreBreakPointForThreadId);

		}
		else if (dwWaitResult == WAIT_TIMEOUT)
		{

		}

	}

	return 0;

}

void Init::SetBreakPoint(int threadId) // If threadId == 0, set BP's to all threads, otherwise set to a certain thread
{

	int currentProcId = GetCurrentProcessId();
	int myThreadId = GetCurrentThreadId();

	HANDLE hTH32 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hTH32 != INVALID_HANDLE_VALUE)
	{

		THREADENTRY32 te32{};
		te32.dwSize = sizeof(THREADENTRY32);

		do
		{

			if (te32.th32OwnerProcessID == currentProcId && te32.th32ThreadID != myThreadId)
			{

				if (threadId != 0)
				{

					if (threadId != te32.th32ThreadID)
						continue;

				}

				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);

				if (hThread == NULL)
					continue;

				SuspendThread(hThread);

				CONTEXT ctx = { 0 };
				ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

				GetThreadContext(hThread, &ctx);

				int value = 0;

				switch (this->debugType)
				{

				case Read:
					value = 983043;
					break;
				case Write:
					value = 851971;
					break;
				case Execute:
					value = 1025;
					break;

				default: value = -1;

				}

				ctx.Dr0 = this->address; // Address to debug
				ctx.Dr7 = value; // Read: 983043 || Write: 851971 || Execute: 1025

				SetThreadContext(hThread, &ctx);
				ResumeThread(hThread);

				CloseHandle(hThread);

			}

		} while (Thread32Next(hTH32, &te32));

	}

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

void Init::Log(const char* text, ...)
{

	va_list va_alist;
	std::ofstream fout;
	char buffer[1024];

	va_start(va_alist, text);
	_vsnprintf_s(buffer, sizeof(buffer), text, va_alist);
	va_end(va_alist);

	fout.open(szLogFile, std::ios::app);

	if (fout.fail())
	{
		fout.close();
		return;
	}

	auto now = std::chrono::system_clock::now();
	auto timeT = std::chrono::system_clock::to_time_t(now);

	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

	tm *date = std::localtime(&timeT);
	auto _ms = ms.count();

	char* pTime = StrToChar("%02d:%02d:%02d.%lu", date->tm_hour, date->tm_min, date->tm_sec, _ms);

	fout << pTime << ": " << buffer << std::endl;
	pTime = NULL;

	fout.close();

}

void Init::MsgBox(const char* str, ...)
{
	va_list vl;
	va_start(vl, str);
	char buff[1024];  // May need to be bigger
	_vsnprintf_s(buff, sizeof(buff), str, vl);
	MessageBoxA(NULL, buff, "", MB_OK);
}
