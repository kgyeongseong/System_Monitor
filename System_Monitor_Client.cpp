#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include "../SysMon/SysMonCommon.h"

// prototypes
int Error(const char* text);
void DisplayInfo(BYTE* buffer, DWORD size);
void DisplayTime(const LARGE_INTEGER& time);
std::string ProcessIdToName(DWORD processId);

int main()
{
	auto hFile = CreateFile(L"\\\\.\\SysMon", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return Error("Failed to open file");

	BYTE buffer[1 << 16]; // 64KB buffer

	while (true) {
		DWORD bytes;
		if (!ReadFile(hFile, buffer, sizeof(buffer), &bytes, nullptr))
			return Error("Failed to read");

		if (bytes != 0)
			DisplayInfo(buffer, bytes);

		Sleep(200);
	}
}

int Error(const char* text)
{
	printf("%s (%d)\n", text, GetLastError());
	getchar();
	return 1;
}

void DisplayInfo(BYTE* buffer, DWORD size)
{
	auto count = size;
	while (count > 0) {
		auto header = (ItemHeader*)buffer;

		switch(header->Type) {
		case ItemType::ProcessExit:
		{
			DisplayTime(header->Time);
			auto info = (ProcessExitInfo*)buffer;
			printf("Process %d Exited\n", info->ProcessId);
			break;
		}

		case ItemType::ProcessCreate:
		{
			DisplayTime(header->Time);
			auto info = (ProcessCreateInfo*)buffer;
			std::wstring commandline((WCHAR*)(buffer + info->CommandLineOffset), info->CommandLineLength);
			std::wstring imagefile((WCHAR*)(buffer + info->ImageFileNameOffset), info->ImageFileNameLength);
			printf("Process %d Created. Command line: %ws ImageFile Name: %ws\n", info->ProcessId, commandline.c_str(), imagefile.c_str());
			break;
		}

		case ItemType::ThreadCreate:
		{
			DisplayTime(header->Time);
			auto info = (ThreadCreateExitInfo*)buffer;
			printf("Thread %d Created in process %d process image name: %s\n", info->ThreadId, info->ProcessId, ProcessIdToName(info->ProcessId).c_str());
			break;
		}

		case ItemType::ThreadExit:
		{
			DisplayTime(header->Time);
			auto info = (ThreadCreateExitInfo*)buffer;
			printf("Thread %d Exited in process %d process image name: %s\n", info->ThreadId, info->ProcessId, ProcessIdToName(info->ProcessId).c_str());
			break;
		}

		case ItemType::ImageLoad:
		{
			DisplayTime(header->Time);
			auto info = (ImageLoadInfo*)buffer;
			printf("Image %ws Loaded in process %d loaded address: 0x%p\n", info->ImageFileName, info->ProcessId, info->LoadAddress);
			break;
		}
		default:
			break;
		}
		buffer += header->Size;
		count -= header->Size;
	}
}

void DisplayTime(const LARGE_INTEGER& time)
{
	SYSTEMTIME st;
	FileTimeToSystemTime((FILETIME*)&time, &st);
	printf("%02d:%02d:%02d.%03d: ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

std::string ProcessIdToName(DWORD processId)
{
	std::string ret;
	HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
	if (handle) {
		DWORD buffSize = 1024;
		CHAR buffer[1024];
		if (QueryFullProcessImageNameA(handle, 0, buffer, &buffSize)) {
			ret = buffer;
		}
		else {
			printf("Error GetModuleBaseNameA : %lu", GetLastError());
		}
		CloseHandle(handle);
	}
	else {
		printf("Error OpenProcess : %lu\n", GetLastError());
	}
	return ret;
}
