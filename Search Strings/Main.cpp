#include <iostream>
#include <vector>
#include <string>
#include <windows.h>
#include <algorithm>
#include <iterator>
#include <TlHelp32.h>

#ifdef _AMD64_
#define _MAX_VALUE ((PVOID)0x000F000000000000)
#define _VALUE ULONG_PTR
#define _Allign 0x7 
#else
#define _MAX_VALUE ((PVOID)0xFFE00000)
#define _VALUE ULONG
#define _Allign 0x3
#endif

#define BUFFER_SIZE 40000

bool invalidChar(char c)
{
	return !isprint(static_cast<unsigned char>(c));
}
void stripUnicode(std::string & str)
{
	str.erase(remove_if(str.begin(), str.end(), invalidChar), str.end());
}

int main(int argc, char **argv)
{
	HANDLE process;
	SIZE_T bytes_read;
	PROCESSENTRY32 processEntry = { 0 };
	MODULEENTRY32 me32{ sizeof(MODULEENTRY32) };
	DWORD pid = -1;
	std::string targetProcess;
	std::string pattern;
	size_t max_char = 64;

	//Get Target Process name
	std::cout << "[+] Process Name : ";
	std::getline(std::cin, targetProcess);

	HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapShot == INVALID_HANDLE_VALUE)
	{

		std::cout << "[!] Failed to CreateToolHelp32Snapshot" << std::endl;
		exit(-1);
	}
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(snapShot, &processEntry))
	{
		do
		{
			if (_stricmp(processEntry.szExeFile, targetProcess.c_str()) == 0)
			{
				//process found
				CloseHandle(snapShot);
				pid = processEntry.th32ProcessID;
				break;
			}
		} while (Process32Next(snapShot, &processEntry));
	}

	if (pid == -1)
	{
		std::cout << "[!] Process not found" << std::endl;
		exit(-1);
	}

	HANDLE snapModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (!snapModule || !::Module32First(snapModule, &me32))
	{
		::CloseHandle(snapModule);
		return 0;
	}

	std::cout << "[+] Process Base Addr : 0x" << std::hex << reinterpret_cast<_VALUE>(me32.modBaseAddr) << std::endl;
	std::cout << "[+] Process Base Size : 0x" << std::hex << (me32.modBaseSize) << std::endl;
	std::cout << "[+] PID : " << pid << std::endl;;

	process = OpenProcess(PROCESS_VM_READ, FALSE, pid);
	if (!process)
	{
		std::cout << "[!] Failed To open Process" << std::endl;
		exit(-1);
	}

	std::cout << "[+] Search strings beginning by : ";
	std::getline(std::cin, pattern);

	std::cout << "[+] Max Size : ";
	std::cin >> max_char;

	char* p = 0;
	std::vector<char> buffer(BUFFER_SIZE);
	char* displayBuffer = new char[max_char];

	std::cout << "[+] Scanning Started ! " << std::endl;

	while (p < (char *)(_MAX_VALUE))
	{
		ReadProcessMemory(process, (LPVOID)p, &buffer[0], BUFFER_SIZE, &bytes_read);

		for (auto pos = buffer.begin(); buffer.end() != (pos = std::search(pos, buffer.end(), pattern.begin(), pattern.end())); ++pos)
		{
			std::string s(pos, pos + max_char);
			stripUnicode(s);
			std::cout << s << std::endl;
		};

		p += BUFFER_SIZE;
	}

	delete displayBuffer;

	std::cout << "[+] Scanning Finished!" << std::endl;

	return 0;
}