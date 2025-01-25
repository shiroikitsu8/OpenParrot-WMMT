// From: https://github.com/BroGamer4256/WanganArcadeLoader

#include <StdInc.h>
#include "Utility/InitFunction.h"
#include "Functions/Global.h"
#include "MinHook.h"
#include <Utility/Hooking.Patterns.h>
#include <thread>
#include <iostream>
#include <Windowsx.h>
#include <Utility/TouchSerial/MT6.h>
#ifdef _M_AMD64
#pragma optimize("", off)
#pragma comment(lib, "Ws2_32.lib")

extern LPCSTR hookPort;
static uintptr_t imageBase;
static unsigned char hasp_buffer[0xD40];
static bool isFreePlay;
static bool isEventMode2P;
static bool isEventMode4P;
static bool ForceFullTune;
static bool ForceNeon;
static bool CarTuneNeonThread;
static const char* ipaddr;

static DWORD mileageValue = 0;
static int NeonColour;

#define HASP_STATUS_OK 0
static unsigned int Hook_hasp_login(int feature_id, void* vendor_code, int hasp_handle) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_login\n");
#endif
	return HASP_STATUS_OK;
}

static unsigned int Hook_hasp_logout(int hasp_handle) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_logout\n");
#endif
	return HASP_STATUS_OK;
}

static unsigned int Hook_hasp_encrypt(int hasp_handle, unsigned char* buffer, unsigned int buffer_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_encrypt\n");
#endif
	return HASP_STATUS_OK;
}

static unsigned int Hook_hasp_decrypt(int hasp_handle, unsigned char* buffer, unsigned int buffer_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_decrypt\n");
#endif
	return HASP_STATUS_OK;
}

static unsigned int Hook_hasp_get_size(int hasp_handle, int hasp_fileid, unsigned int* hasp_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_get_size\n");
#endif
	* hasp_size = 0xD40; // Max addressable size by the game... absmax is 4k
	return HASP_STATUS_OK;
}

static unsigned int Hook_hasp_read(int hasp_handle, int hasp_fileid, unsigned int offset, unsigned int length, unsigned char* buffer) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_read\n");
#endif
	memcpy(buffer, hasp_buffer + offset, length);
	return HASP_STATUS_OK;
}

static unsigned int Hook_hasp_write(int hasp_handle, int hasp_fileid, unsigned int offset, unsigned int length, unsigned char* buffer) {
	return HASP_STATUS_OK;
}

typedef int (WINAPI* BIND)(SOCKET, CONST SOCKADDR*, INT);
static BIND pbind = NULL;

static unsigned int WINAPI Hook_bind(SOCKET s, const sockaddr* addr, int namelen) {
	sockaddr_in bindAddr = { 0 };
	bindAddr.sin_family = AF_INET;
	bindAddr.sin_addr.s_addr = inet_addr("192.168.96.20");
	bindAddr.sin_port = htons(50765);
	if (addr == (sockaddr*)&bindAddr) {
		sockaddr_in bindAddr2 = { 0 };
		bindAddr2.sin_family = AF_INET;
		bindAddr2.sin_addr.s_addr = inet_addr(ipaddr);
		bindAddr2.sin_port = htons(50765);
		return pbind(s, (sockaddr*)&bindAddr2, namelen);
	}
	else {
		return pbind(s, addr, namelen);

	}
}

static BOOL FileExists(char* szPath)
{
	DWORD dwAttrib = GetFileAttributesA(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

static int ReturnTrue()
{
	return 1;
}

static BYTE GenerateChecksum(unsigned char* myArray, int index, int length)
{
	BYTE crc = 0;
	for (int i = 0; i < length; i++)
	{
		crc += myArray[index + i];
	}
	return crc & 0xFF;
}

static void GenerateDongleData(bool isTerminal)
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
	if (isTerminal)
	{
		memcpy(hasp_buffer + 0xD00, "285011501138", 12);
		hasp_buffer[0xD3E] = GenerateChecksum(hasp_buffer, 0xD00, 62);
		hasp_buffer[0xD3F] = hasp_buffer[0xD3E] ^ 0xFF;
	}
	else
	{
		memcpy(hasp_buffer + 0xD00, "285013501138", 12);
		hasp_buffer[0xD3E] = GenerateChecksum(hasp_buffer, 0xD00, 62);
		hasp_buffer[0xD3F] = hasp_buffer[0xD3E] ^ 0xFF;
	}
}

static HWND mt6Hwnd;

typedef BOOL(WINAPI* ShowWindow_t)(HWND, int);
static ShowWindow_t pShowWindow;

// Hello Win32 my old friend...
typedef LRESULT(WINAPI* WindowProcedure_t)(HWND, UINT, WPARAM, LPARAM);
static WindowProcedure_t pMaxituneWndProc;

static BOOL gotWindowSize = FALSE;

static LRESULT Hook_WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (!gotWindowSize)
	{
		mt6SetDisplayParams(hwnd);
		gotWindowSize = TRUE;
	}

	if (msg == WM_LBUTTONDOWN ||
		msg == WM_LBUTTONUP)
	{
		mt6SetTouchData(lParam, msg == WM_LBUTTONDOWN, false);
		return 0;
	}

	if (msg == WM_POINTERDOWN ||
		msg == WM_POINTERUP)
	{
		mt6SetTouchData(lParam, msg == WM_POINTERDOWN, true);
		return 0;
	}

	return pMaxituneWndProc(hwnd, msg, wParam, lParam);
}

static BOOL Hook_ShowWindow(HWND hwnd, int nCmdShow)
{
	SetWindowLongPtrW(hwnd, -4, (LONG_PTR)Hook_WndProc);
	ShowCursor(1);

	mt6Hwnd = hwnd;
	return pShowWindow(hwnd, nCmdShow);
}

typedef void (WINAPI* OutputDebugStringA_t)(LPCSTR);

static void Hook_OutputDebugStringA(LPCSTR str)
{
	printf("debug> %s", str);
}


static InitFunction Wmmt6RRFunc([]()
	{
		// Alloc debug console
		FreeConsole();
		AllocConsole();
		SetConsoleTitle(L"Maxitune6RR Console");

		FILE* pNewStdout = nullptr;
		FILE* pNewStderr = nullptr;
		FILE* pNewStdin = nullptr;

		::freopen_s(&pNewStdout, "CONOUT$", "w", stdout);
		::freopen_s(&pNewStderr, "CONOUT$", "w", stderr);
		::freopen_s(&pNewStdin, "CONIN$", "r", stdin);
		std::cout.clear();
		std::cerr.clear();
		std::cin.clear();
		std::wcout.clear();
		std::wcerr.clear();
		std::wcin.clear();

		puts("hello there, maxitune");

		bool isTerminal = false;
		if (ToBool(config["General"]["TerminalMode"]))
		{
			isTerminal = true;
		}

		std::string networkip = config["General"]["NetworkAdapterIP"];
		if (!networkip.empty())
		{
			ipaddr = networkip.c_str();
		}

		hookPort = "COM3";
		imageBase = (uintptr_t)GetModuleHandleA(0);
		MH_Initialize();

		// Hook dongle funcs
		MH_CreateHookApi(L"hasp_windows_x64_30382.dll", "hasp_write", Hook_hasp_write, NULL);
		MH_CreateHookApi(L"hasp_windows_x64_30382.dll", "hasp_read", Hook_hasp_read, NULL);
		MH_CreateHookApi(L"hasp_windows_x64_30382.dll", "hasp_get_size", Hook_hasp_get_size, NULL);
		MH_CreateHookApi(L"hasp_windows_x64_30382.dll", "hasp_decrypt", Hook_hasp_decrypt, NULL);
		MH_CreateHookApi(L"hasp_windows_x64_30382.dll", "hasp_encrypt", Hook_hasp_encrypt, NULL);
		MH_CreateHookApi(L"hasp_windows_x64_30382.dll", "hasp_logout", Hook_hasp_logout, NULL);
		MH_CreateHookApi(L"hasp_windows_x64_30382.dll", "hasp_login", Hook_hasp_login, NULL);
		MH_CreateHookApi(L"WS2_32", "bind", Hook_bind, reinterpret_cast<LPVOID*>(&pbind));

		MH_CreateHookApi(L"kernel32", "OutputDebugStringA", Hook_OutputDebugStringA, NULL);
		// CreateFile* hooks are in the JVS FILE

		// Give me the HWND please maxitune
		MH_CreateHookApi(L"user32", "ShowWindow", Hook_ShowWindow, reinterpret_cast<LPVOID*>(&pShowWindow));
		
		// Hook the window procedure
		pMaxituneWndProc = (WindowProcedure_t)(hook::get_pattern("48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 8B EA BA EB FF FF FF 49 8B F9 49 8B F0 48 8B D9 FF 15 ? ? ? 00 48 85 C0 74 1D 4C", 0));

		GenerateDongleData(isTerminal);

		// Skip weird camera init that stucks entire pc on certain brands. TESTED ONLY ON 05!!!!
		if (ToBool(config["General"]["WhiteScreenFix"]))
		{
			injector::WriteMemory<DWORD>(hook::get_pattern("48 8B C4 55 57 41 54 41 55 41 56 48 8D 68 A1 48 81 EC 90 00 00 00 48 C7 45 D7 FE FF FF FF 48 89 58 08 48 89 70 18 45 33 F6 4C 89 75 DF 33 C0 48 89 45 E7", 0), 0x90C3C032, true);
		}

		// Best LAN setting by doomertheboomer
		injector::WriteMemory<BYTE>(imageBase + 0xB41DAA, 0xEB, true); //content router patch
		injector::MakeNOP(imageBase + 0x732F36, 2, true);

		// First auth error skip
		injector::WriteMemory<BYTE>(imageBase + 0x743942, 0xEB, true);

		if (isTerminal)
		{
			// More dongle error shit?
			safeJMP(hook::get_pattern("8B 01 0F B6 40 78 C3 CC CC CC CC"), ReturnTrue);
		}
		else
		{
			// Terminal on same machine check.
			injector::MakeNOP(hook::get_pattern("74 ? 80 7B 31 00 75 ? 48 8B 43 10 80 78 31 00 75 1A 48 8B D8 48 8B 00 80 78 31 00 75 ? 48 8B D8"), 2);
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

		// Fix dongle error (can be triggered by various USB hubs, dongles
		injector::MakeNOP(imageBase + 0x9C800F, 2, true);
		injector::WriteMemory<BYTE>(imageBase + 0x7420F9, 0x0, true);

		injector::MakeNOP(imageBase + 0x7436E4, 6, true);
		injector::WriteMemory<uint8_t>(imageBase + 0x7436F9, 0xEB, true);

		MH_EnableHook(MH_ALL_HOOKS);
	}, GameID::WMMT6RR);
#endif
#pragma optimize("", on)