#include <StdInc.h>
#include "Utility/InitFunction.h"
#include "Functions/Global.h"
#include <filesystem>
#include <iostream>
#include <cstdint>
#include <fstream>
#include "MinHook.h"
#include <Utility/Hooking.Patterns.h>
#include <chrono>
#include <thread>
#ifdef _M_AMD64
#pragma optimize("", off)
#pragma comment(lib, "Ws2_32.lib")

extern LPCSTR hookPort;
uintptr_t imageBasedxplus;
static unsigned char hasp_buffer[0xD40];
static bool isFreePlay;
static bool isEventMode2P;
static bool isEventMode4P;
const char *ipaddrdxplus;

// MUST DISABLE IC CARD, FFB MANUALLY N MT5DX+




#define HASP_STATUS_OK 0
unsigned int dxpHook_hasp_login(int feature_id, void* vendor_code, int hasp_handle) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_login\n");
#endif
	return HASP_STATUS_OK;
}

unsigned int dxpHook_hasp_logout(int hasp_handle) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_logout\n");
#endif
	return HASP_STATUS_OK;
}

unsigned int dxpHook_hasp_encrypt(int hasp_handle, unsigned char* buffer, unsigned int buffer_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_encrypt\n");
#endif
	return HASP_STATUS_OK;
}

unsigned int dxpHook_hasp_decrypt(int hasp_handle, unsigned char* buffer, unsigned int buffer_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_decrypt\n");
#endif
	return HASP_STATUS_OK;
}

unsigned int dxpHook_hasp_get_size(int hasp_handle, int hasp_fileid, unsigned int* hasp_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_get_size\n");
#endif
	*hasp_size = 0xD40; // Max addressable size by the game... absmax is 4k
	return HASP_STATUS_OK;
}

unsigned int dxpHook_hasp_read(int hasp_handle, int hasp_fileid, unsigned int offset, unsigned int length, unsigned char* buffer) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_read\n");
#endif
	memcpy(buffer, hasp_buffer + offset, length);
	return HASP_STATUS_OK;
}

unsigned int dxpHook_hasp_write(int hasp_handle, int hasp_fileid, unsigned int offset, unsigned int length, unsigned char* buffer) {
	return HASP_STATUS_OK;
}

//set system date patch by pockywitch
typedef bool (WINAPI* SETSYSTEMTIME)(SYSTEMTIME* in);
SETSYSTEMTIME pSetSystemTime = NULL;

bool WINAPI Hook_SetSystemTime(SYSTEMTIME* in)
{
	return TRUE;
}


// ******************************************** //
// ************ Debug Data Logging ************ //
// ******************************************** //

// ************* Global Variables ************* //

// **** String Variables

// Debugging event log file
std::string logfileDxp = "wmmt5dxp_errors.txt";

// writeLog(filename: String, message: String): Int
// Given a filename string and a message string, appends
// the message to the given file.
static int writeLog(std::string filename, std::string message)
{
	// Log file to write to
	std::ofstream eventLog;

	// Open the filename provided (append mode)
	eventLog.open(filename, std::ios_base::app);

	// File open success
	if (eventLog.is_open()) 
	{
		// Write the message to the file
		eventLog << message;

		// Close the log file handle
		eventLog.close();

		// Success
		return 0;
	}
	else // File open failed
	{
		// Failure
		return 1;
	}
}

// writeDump(filename: Char*, data: unsigned char *, size: size_t): Int
static int writeDump(char * filename, unsigned char * data, size_t size)
{
	// Open the file with the provided filename
	FILE* file = fopen(filename, "wb");

	// File opened successfully
	if (file)
	{
		// Write the data to the file
		fwrite((void*)data, 1, size, file);

		// Close the file
		fclose(file);

		// Return success status
		return 0;
	}
	else // Failed to open
	{
		// Return failure status
		return 1;
	}
}


static int ReturnTrue()
{
	return 1;
}

void GenerateDongleDataDxp(bool isTerminal)
{
	memset(hasp_buffer, 0, 0xD40);
	hasp_buffer[0] = 0x01;
	hasp_buffer[0x13] = 0x01;
	hasp_buffer[0x17] = 0x0A;
	hasp_buffer[0x1B] = 0x04;
	hasp_buffer[0x1C] = 0x3B;
	hasp_buffer[0x1D] = 0x6B;
	hasp_buffer[0x1E] = 0x40;
	hasp_buffer[0x1F] = 0x87;

	hasp_buffer[0x23] = 0x01;
	hasp_buffer[0x27] = 0x0A;
	hasp_buffer[0x2B] = 0x04;
	hasp_buffer[0x2C] = 0x3B;
	hasp_buffer[0x2D] = 0x6B;
	hasp_buffer[0x2E] = 0x40;
	hasp_buffer[0x2F] = 0x87;

	if(isTerminal)
	{
		memcpy(hasp_buffer + 0xD00, "278311042069", 12); //272211990002
		hasp_buffer[0xD3E] = 0x6B;
		hasp_buffer[0xD3F] = 0x94;
	}
	else
	{
		memcpy(hasp_buffer + 0xD00, "278313042069", 12); //272213990002
		hasp_buffer[0xD3E] = 0x6D;
		hasp_buffer[0xD3F] = 0x92;
	}
}


// Wmmt5Func([]()): InitFunction
// Performs the initial startup tasks for 
// maximum tune 5, including the starting 
// of required subprocesses.
static InitFunction Wmmt5Func([]()
{

	// Records if terminal mode is enabled
	bool isTerminal = false;

	// If terminal mode is set in the general settings
	if (ToBool(config["General"]["TerminalMode"]))
	{
		// Terminal mode is set
		isTerminal = true;
	}
	
	// Get the network adapter ip address from the general settings
	std::string networkip = config["General"]["NetworkAdapterIP"];

	// If the ip address is not blank
	if (!networkip.empty())
	{
		// Overwrite the default ip address
		ipaddrdxplus = networkip.c_str();
	}

	hookPort = "COM3";
	imageBasedxplus = (uintptr_t)GetModuleHandleA(0);

	MH_Initialize();

	// Hook dongle funcs
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_write", dxpHook_hasp_write, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_read", dxpHook_hasp_read, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_get_size", dxpHook_hasp_get_size, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_decrypt", dxpHook_hasp_decrypt, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_encrypt", dxpHook_hasp_encrypt, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_logout", dxpHook_hasp_logout, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_login", dxpHook_hasp_login, NULL);

	GenerateDongleDataDxp(isTerminal);

	//load banapass emu
	auto mod = LoadLibraryA(".\\openBanaW5p.dll");


	// Prevents game from setting time, thanks pockywitch!
	MH_CreateHookApi(L"KERNEL32", "SetSystemTime", Hook_SetSystemTime, reinterpret_cast<LPVOID*>(&pSetSystemTime));

	injector::WriteMemory<uint8_t>(hook::get_pattern("85 C9 0F 94 C0 84 C0 0F 94 C0 84 C0 75 ? 40 32 F6 EB ?", 0x15), 0, true); //patches out dongle error2 (doomer)
	injector::MakeNOP(hook::get_pattern("83 C0 FD 83 F8 01 76 ? 49 8D ? ? ? ? 00 00"), 6);

	if (ToBool(config["General"]["WhiteScreenFix"]))
	{
		injector::WriteMemory<DWORD>(hook::get_pattern("48 8B C4 55 57 41 54 41 55 41 56 48 8D 68 A1 48 81 EC 90 00 00 00 48 C7 45 D7 FE FF FF FF 48 89 58 08 48 89 70 18 45 33 F6 4C 89 75 DF 33 C0 48 89 45 E7", 0), 0x90C3C032, true);
	}

	{
		auto location = hook::get_pattern<char>("41 3B C7 74 0E 48 8D 8F B8 00 00 00 BA F6 01 00 00 EB 6E 48 8D 8F A0 00 00 00");
		
		injector::WriteMemory<uint8_t>(location + 3, 0xEB, true); //patches content router (doomer)

		// Skip some jnz
		injector::MakeNOP(location + 0x22, 2); //patches ip addr error again (doomer)

		// Skip some jnz
		injector::MakeNOP(location + 0x33, 2); //patches ip aaddr error(doomer)
	}

	// Terminal mode is off
	if (!isTerminal)
	{
		injector::MakeNOP(imageBasedxplus + 0x9F2BB3, 2); //terminal on same machine patch

		// If terminal emulator is enabled
		if (ToBool(config["General"]["TerminalEmulator"]))
		{

		}
	}
	
	else
	{
		// Patch some func to 1
		// 
		// FOUND ON 21, 10, 1
		// NOT FOUND:
		//safeJMP(imageBase + 0x7BE440, ReturnTrue);
		//safeJMP(hook::get_pattern("0F B6 41 05 2C 30 3C 09 77 04 0F BE C0 C3 83 C8 FF C3"), ReturnTrue);
		//safeJMP(imageBase + 0x89D420, ReturnTrue);

		// Patch some func to 1
		// 40 53 48 83 EC 20 48 83 39 00 48 8B D9 75 28 48 8D ?? ?? ?? ?? 00 48 8D ?? ?? ?? ?? 00 41 B8 ?? ?? 00 00 FF 15 ?? ?? ?? ?? 4C 8B 1B 41 0F B6 43 78
		// FOUND ON 21, 10, 1
		//safeJMP(imageBase + 0x7CF8D0, ReturnTrue); 
		//safeJMP(hook::get_pattern("40 53 48 83 EC 20 48 83 39 00 48 8B D9 75 11 48 8B 0D C2"), ReturnTrue);
		//safeJMP(imageBase + 0x8B5190, ReturnTrue); 
	}
	

	auto chars = { 'F', 'G' };

	for (auto cha : chars)
	{
		auto patterns = hook::pattern(va("%02X 3A 2F", cha));

		if (patterns.size() > 0)
		{
			for (int i = 0; i < patterns.size(); i++)
			{
				char* text = patterns.get(i).get<char>(0);
				std::string text_str(text);

				std::string to_replace = va("%c:/", cha);
				std::string replace_with = va("./%c", cha);

				std::string replaced = text_str.replace(0, to_replace.length(), replace_with);

				injector::WriteMemoryRaw(text, (char*)replaced.c_str(), replaced.length() + 1, true);
			}
		}
	}

	{
		// Enable all print
		injector::MakeNOP(imageBasedxplus + 0x898BD3, 6);
	}

	MH_EnableHook(MH_ALL_HOOKS);

}, GameID::WMMT5DXPlus);
#endif
#pragma optimize("", on)