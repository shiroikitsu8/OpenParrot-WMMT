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

static LPSTR terminalIP;
static LPSTR routerIP;
static LPSTR cab1IP;
static LPSTR cab2IP;
static LPSTR cab3IP;
static LPSTR cab4IP;

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
	if (addr == (sockaddr*)& bindAddr) {
		sockaddr_in bindAddr2 = { 0 };
		bindAddr2.sin_family = AF_INET;
		bindAddr2.sin_addr.s_addr = inet_addr(terminalIP);
		bindAddr2.sin_port = htons(50765);
		return pbind(s, (sockaddr*)& bindAddr2, namelen);
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

static BYTE GenerateChecksum(unsigned char *myArray, int index, int length)
{
	BYTE crc = 0;
	for(int i = 0; i < length; i++)
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
		memcpy(hasp_buffer + 0xD00, "290811990002", 12); // not sure these are OK, since its from google lol.
		hasp_buffer[0xD3E] = GenerateChecksum(hasp_buffer, 0xD00, 62);
		hasp_buffer[0xD3F] = hasp_buffer[0xD3E] ^ 0xFF;
	}
	else
	{
		memcpy(hasp_buffer + 0xD00, "280813401138", 12);
		hasp_buffer[0xD3E] = GenerateChecksum(hasp_buffer, 0xD00, 62);
		hasp_buffer[0xD3F] = hasp_buffer[0xD3E] ^ 0xFF;
	}
}

extern int* ffbOffset;
extern int* ffbOffset2;
extern int* ffbOffset3;
extern int* ffbOffset4;

static HWND mt6Hwnd;

typedef BOOL(WINAPI* ShowWindow_t)(HWND, int);
static ShowWindow_t pShowWindow;


// Hello Win32 my old friend...
typedef LRESULT(WINAPI* WindowProcedure_t)(HWND, UINT, WPARAM, LPARAM);
static WindowProcedure_t pMaxituneWndProc;

static BOOL gotWindowSize = FALSE;
static unsigned displaySizeX = 0;
static unsigned displaySizeY = 0;
static float scaleFactorX = 0.0f;
static float scaleFactorY = 0.0f;

static LRESULT Hook_WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (!gotWindowSize)
	{
		displaySizeX = GetSystemMetrics(SM_CXSCREEN);
		displaySizeY = GetSystemMetrics(SM_CYSCREEN);
		scaleFactorX = static_cast<float>(displaySizeX) / 1360.0f;
		scaleFactorY = static_cast<float>(displaySizeY) / 768.0f;
		printf("display is %dx%d (scale factor of %f, %f)\n", displaySizeX, displaySizeY, scaleFactorX, scaleFactorY);
		gotWindowSize = TRUE;
	}

	if (msg == WM_LBUTTONDOWN ||
		msg == WM_LBUTTONUP)
	{
		unsigned short mx = GET_X_LPARAM(lParam);
		unsigned short my = GET_Y_LPARAM(lParam);

		//unsigned short trueMy = 768 - my;

		float scaledMx = static_cast<float>(mx) / 1360.f;
		float scaledMy = static_cast<float>(my) / 768.f;

		scaledMy = 1.0f - scaledMy;

		scaledMx *= scaleFactorX;
		scaledMy *= scaleFactorY;

		unsigned short trueMx = static_cast<int>(scaledMx * 16383.0f);
		unsigned short trueMy = static_cast<int>(scaledMy * 16383.0f);
		trueMy += 9500; // Cheap hack, todo do the math better!!

		//mx *= (16383 / 1360);
		//trueMy *= (16383 / 1360);

		printf("%d %d\n", trueMx, trueMy);
		mt6SetTouchParams(trueMx, trueMy, msg == WM_LBUTTONDOWN);

		printf("MOUSE %s (%d, %d)\n", msg == WM_LBUTTONDOWN ? "DOWN" : "UP  ", mx, my);
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

typedef INT(WSAAPI* WsaStringToAddressA_t)(LPSTR, INT, LPWSAPROTOCOL_INFOA, LPSOCKADDR, LPINT);
static WsaStringToAddressA_t gWsaStringToAddressA;


//#define LOCAL_IP "192.168.100.10"
//#define ROUTER_IP "192.168.100.1"
#define LOCALHOST "127.0.0.1"




static INT WSAAPI Hook_WsaStringToAddressA(
	_In_ LPSTR AddressString,
	_In_ INT AddressFamily,
	_In_opt_ LPWSAPROTOCOL_INFOA lpProtocolInfo,
	_Out_ LPSOCKADDR lpAddress,
	_Inout_ LPINT lpAddressLength
)
{


	if (strcmp(AddressString, "192.168.92.254") == 0)
	{
		return gWsaStringToAddressA(
			routerIP,
			AddressFamily,
			lpProtocolInfo,
			lpAddress,
			lpAddressLength
		);
	}

	if (strcmp(AddressString, "192.168.92.253") == 0)
	{
		return gWsaStringToAddressA(
			routerIP,
			AddressFamily,
			lpProtocolInfo,
			lpAddress,
			lpAddressLength
		);
	}

	if (strcmp(AddressString, "192.168.92.11") == 0)
	{
		return gWsaStringToAddressA(
			cab1IP,
			AddressFamily,
			lpProtocolInfo,
			lpAddress,
			lpAddressLength
		);
	}

	if (strcmp(AddressString, "192.168.92.12") == 0)
	{
		return gWsaStringToAddressA(
			cab2IP,
			AddressFamily,
			lpProtocolInfo,
			lpAddress,
			lpAddressLength
		);
	}

	if (strcmp(AddressString, "192.168.92.13") == 0)
	{
		return gWsaStringToAddressA(
			cab3IP,
			AddressFamily,
			lpProtocolInfo,
			lpAddress,
			lpAddressLength
		);
	}

	if (strcmp(AddressString, "192.168.92.14") == 0)
	{
		return gWsaStringToAddressA(
			cab4IP,
			AddressFamily,
			lpProtocolInfo,
			lpAddress,
			lpAddressLength
		);
	}

	if (strcmp(AddressString, "192.168.92.20") == 0)
	{
		return gWsaStringToAddressA(
			terminalIP,
			AddressFamily,
			lpProtocolInfo,
			lpAddress,
			lpAddressLength
		);
	}

	return gWsaStringToAddressA(
		AddressString,
		AddressFamily,
		lpProtocolInfo,
		lpAddress,
		lpAddressLength
	);
}

typedef INT(WSAAPI* getaddrinfo_t)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
static getaddrinfo_t ggetaddrinfo;

static INT WSAAPI Hook_getaddrinfo(
	_In_opt_ PCSTR pNodeName,
	_In_opt_ PCSTR pServiceName,
	_In_opt_ const ADDRINFOA* pHints,
	_Out_ PADDRINFOA* ppResult
)
{
	if (pNodeName && strcmp(pNodeName, "192.168.92.253") == 0)
	{
		return ggetaddrinfo(routerIP, pServiceName, pHints, ppResult);
	}

	return ggetaddrinfo(pNodeName, pServiceName, pHints, ppResult);
}

static __int64 nbamUsbFinderRelease()
{
	return 0;
}

static __int64 nbamUsbFinderInitialize()
{
	return 0;
}

static __int64 __fastcall nbamUsbFinderGetSerialNumber(int a1, char* a2)
{
	static char* serial = "280813401138";
	memcpy(a2, serial, strlen(serial));
	return 0;
}
static InitFunction Wmmt6RFunc([]()
{
	FreeConsole();
	AllocConsole();
	SetConsoleTitle(L"Maxitune6R Console");

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

	puts("hello, maxitune 6R");

	// folder for path redirections
	CreateDirectoryA(".\\TP", nullptr);

	bool isTerminal = false;
	if (ToBool(config["General"]["TerminalMode"]))
	{
		isTerminal = true;
	}

	std::string TERMINAL_IP = config["General"]["TerminalIP"];
	if (!TERMINAL_IP.empty())
	{
		char* theIp = (char*)malloc(sizeof(char) * 255);
		memset(theIp, 0, sizeof(char) * 255);
		strcpy(theIp, TERMINAL_IP.c_str());
		terminalIP = (LPSTR)theIp;
	}
	else
	{
		terminalIP = "127.0.0.1";
	}

	std::string ROUTER_IP = config["General"]["RouterIP"];
	if (!ROUTER_IP.empty())
	{
		char* theIp = (char*)malloc(sizeof(char) * 255);
		memset(theIp, 0, sizeof(char) * 255);
		strcpy(theIp, ROUTER_IP.c_str());
		routerIP = (LPSTR)theIp;
	}
	else
	{
		routerIP = "192.168.86.1";
	}

	std::string Cab_1_IP = config["General"]["Cab1IP"];
	if (!Cab_1_IP.empty())
	{
		char* theIp = (char*)malloc(sizeof(char) * 255);
		memset(theIp, 0, sizeof(char) * 255);
		strcpy(theIp, Cab_1_IP.c_str());
		cab1IP = (LPSTR)theIp;
	}
	else
	{
		cab1IP = "192.168.255.255";
	}

	std::string Cab_2_IP = config["General"]["Cab2IP"];
	if (!Cab_2_IP.empty())
	{
		char* theIp = (char*)malloc(sizeof(char) * 255);
		memset(theIp, 0, sizeof(char) * 255);
		strcpy(theIp, Cab_2_IP.c_str());
		cab2IP = (LPSTR)theIp;
	}
	else
	{
		cab2IP = "192.168.255.255";
	}

	std::string Cab_3_IP = config["General"]["Cab3IP"];
	if (!Cab_3_IP.empty())
	{
		char* theIp = (char*)malloc(sizeof(char) * 255);
		memset(theIp, 0, sizeof(char) * 255);
		strcpy(theIp, Cab_3_IP.c_str());
		cab3IP = (LPSTR)theIp;
	}
	else
	{
		cab3IP = "192.168.255.255";
	}

	std::string Cab_4_IP = config["General"]["Cab4IP"];
	if (!Cab_4_IP.empty())
	{
		char* theIp = (char*)malloc(sizeof(char) * 255);
		memset(theIp, 0, sizeof(char) * 255);
		strcpy(theIp, Cab_4_IP.c_str());
		cab4IP = (LPSTR)theIp;
	}
	else
	{
		cab4IP = "192.168.255.255";
	}

	hookPort = "COM3";
	imageBase = (uintptr_t)GetModuleHandleA(0);
	MH_Initialize();

	// Hook dongle funcs
	MH_CreateHookApi(L"hasp_windows_x64_28756.dll", "hasp_write", Hook_hasp_write, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_28756.dll", "hasp_read", Hook_hasp_read, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_28756.dll", "hasp_get_size", Hook_hasp_get_size, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_28756.dll", "hasp_decrypt", Hook_hasp_decrypt, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_28756.dll", "hasp_encrypt", Hook_hasp_encrypt, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_28756.dll", "hasp_logout", Hook_hasp_logout, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_28756.dll", "hasp_login", Hook_hasp_login, NULL);
	MH_CreateHookApi(L"nbamUsbFinder.dll", "nbamUsbFinderGetSerialNumber", nbamUsbFinderGetSerialNumber, NULL);
	MH_CreateHookApi(L"nbamUsbFinder.dll", "nbamUsbFinderInitialize", nbamUsbFinderInitialize, NULL);
	MH_CreateHookApi(L"nbamUsbFinder.dll", "nbamUsbFinderRelease", nbamUsbFinderRelease, NULL);

	MH_CreateHookApi(L"WS2_32", "bind", Hook_bind, reinterpret_cast<LPVOID*>(&pbind));

	GenerateDongleData(isTerminal);

	MH_CreateHookApi(L"kernel32", "OutputDebugStringA", Hook_OutputDebugStringA, NULL);
	// CreateFile* hooks are in the JVS FILE


	// Network hooks
	MH_CreateHookApi(L"Ws2_32", "WSAStringToAddressA", Hook_WsaStringToAddressA, reinterpret_cast<LPVOID*>(&gWsaStringToAddressA));
	MH_CreateHookApi(L"Ws2_32", "getaddrinfo", Hook_getaddrinfo, reinterpret_cast<LPVOID*>(&ggetaddrinfo));

	// Give me the HWND please maxitune
	MH_CreateHookApi(L"user32", "ShowWindow", Hook_ShowWindow, reinterpret_cast<LPVOID*>(&pShowWindow));
	//MH_CreateHookApi(L"kernel32", "ReadFile", Hook_ReadFile, reinterpret_cast<LPVOID*>(&pReadFile))

	pMaxituneWndProc = (WindowProcedure_t)(imageBase + 0xC69BB0);

	//injector::WriteMemory<uint8_t>(imageBase + 0x716BC6, 0, true); 	// pls check

	// system error fix
	//injector::WriteMemory<uint8_t>(hook::get_pattern("0F 94 C0 84 C0 0F 94 C0 84 C0 75 05 45 32 ? EB", 0x13), 0, true);

	// Skip weird camera init that stucks entire pc on certain brands. TESTED ONLY ON 05!!!!
	if (ToBool(config["General"]["WhiteScreenFix"]))
	{
		injector::WriteMemory<DWORD>(hook::get_pattern("48 8B C4 55 57 41 54 41 55 41 56 48 8D 68 A1 48 81 EC 90 00 00 00 48 C7 45 D7 FE FF FF FF 48 89 58 08 48 89 70 18 45 33 F6 4C 89 75 DF 33 C0 48 89 45 E7", 0), 0x90C3C032, true);
	}

	//injector::MakeNOP(hook::get_pattern("45 33 C0 BA 65 09 00 00 48 8D 4D B0 E8 ? ? ? ? 48 8B 08", 12), 5);

	//auto location = hook::get_pattern<char>("48 83 EC 28 33 D2 B9 70 00 02 00 E8 ? ? ? ? 85 C0 79 06");
	//injector::WriteMemory<uint8_t>(location + 0x12, 0xEB, true);

	// First auth error skip
	//injector::WriteMemory<BYTE>(imageBase + 0x71839B, 0xEB, true);
	
	if (isTerminal)
	{
		//safeJMP(hook::get_pattern("8B 01 0F B6 40 78 C3 CC CC CC CC"), ReturnTrue);
		//safeJMP(hook::get_pattern("0F B6 41 05 2C 30 3C 09 77 04 0F BE C0 C3 83 C8 FF C3"), ReturnTrue);
	}
	else
	{
		// terminal on same machine (from mt6)
		//injector::MakeNOP(hook::get_pattern("74 ? 80 7B 31 00 75 ? 48 8B 43 10 80 78 31 00 75 1A 48 8B D8 48 8B 00 80 78 31 00 75 ? 48 8B D8"), 2);
		
		/*injector::WriteMemory<WORD>(imageBase + 0x718FA1, 0x00D2, true); // pls check
		injector::WriteMemory<BYTE>(imageBase + 0x20EC3A, 0x90, true);
		injector::WriteMemory<BYTE>(imageBase + 0x20EC3B, 0x90, true);
		injector::WriteMemory<BYTE>(imageBase + 0x20EC4B, 0x90, true);
		injector::WriteMemory<BYTE>(imageBase + 0x20EC4C, 0x90, true);
		injector::WriteMemory<BYTE>(imageBase + 0x20EC51, 0x90, true);
		injector::WriteMemory<BYTE>(imageBase + 0x20EC52, 0x90, true);*/
	}

	// Enable all print
	//injector::WriteMemory<BYTE>(imageBase + 0x9891B3, 0xEB, true);

	// Dongle crap
	injector::WriteMemory<BYTE>(imageBase + 0x71683A, 0xEB, true);
	injector::WriteMemory<WORD>(imageBase + 0x716978, 0xE990, true);

	// Skip error modals
	//injector::MakeNOP(imageBase + 0x7089F4, 2);

	//Fix crash when saving story mode and Time attack, if the error isn't handled then it doesnt crash?????
	//injector::WriteMemory<uint8_t>(imageBase + 0x8A6B5F, 0xEB, true);

	// path fixes
	injector::WriteMemoryRaw(imageBase + 0x1412758, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1412778, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1412798, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14127B8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14127D8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14127F8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1412818, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1412838, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1412858, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1412870, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C7388, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C73A0, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C73B8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C73E0, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C7408, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C7420, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C7438, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C7448, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C7458, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C7470, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C7488, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C74A8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C74C8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C74D8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C74E8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C7500, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C7518, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C7530, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C7548, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C7560, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C7578, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C7590, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C75A8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14C75C0, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14CFC48, "TP", 2, true); // F:/contents/
	injector::WriteMemoryRaw(imageBase + 0x151F6D0, "TP/contents/", 12, true); // F:contents/
	injector::WriteMemoryRaw(imageBase + 0x151F6E0, "TP/contents/", 12, true);	// G:contents/
	injector::WriteMemoryRaw(imageBase + 0x1575C50, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1575C68, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x15769C8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x15769E0, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x15769F8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1576A20, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1576A48, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1576A60, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x15774C0, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x15774E0, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x157699C, "TP", 2, true); // F:/
	injector::WriteMemoryRaw(imageBase + 0x14D2318, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14D2B20, "TP", 2, true);

	// Fix dongle error (can be triggered by various USB hubs, dongles
	injector::MakeNOP(imageBase + 0x993FFF, 2, true);

	// Save story stuff (only 05)
	{
		// skip erasing of temp card data
		//injector::WriteMemory<uint8_t>(imageBase + 0xB2CF33, 0xEB, true);
		// Skip erasing of temp card
		//safeJMP(imageBase + 0x6ADBF0, LoadGameData); //Disabled temporary to stop users copying WMMT6 save to 6R until save works correctly so load has a purpose!!
		//safeJMP(imageBase + 0x6C7270, ReturnTrue);
	}

	MH_EnableHook(MH_ALL_HOOKS);

}, GameID::WMMT6R);
#endif
#pragma optimize("", on)