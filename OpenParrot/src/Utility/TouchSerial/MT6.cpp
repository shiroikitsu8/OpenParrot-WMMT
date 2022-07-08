#include "MT6.h"
#include <vector>

typedef struct {
	unsigned short x;
	unsigned short y;
	char status;
} touchscreenevent;

static HANDLE vecMutex;
static std::vector<touchscreenevent> eventVector;

// FROM GAME
char CMD_RESET[3] = {
	0x01, 0x52, 0x0d
};

char CMD_DIAGNOSTICS[4] = {
	0x01, 0x44, 0x58, 0x0d
};

// TO GAME
char OK_RESPONSE[3] = {
	0x01, 0x30, 0x0d
};

DWORD mt6WritePort(HANDLE port, char data[], unsigned length)
{
	DWORD numWritten = 0;
	WriteFile(port, data, length, &numWritten, NULL);
	return numWritten;
}

DWORD mt6SerialTouchThread(HANDLE port)
{
	char fileBuf[32];
	puts("testing testing");

	/* {
		char startupBuf[3] = { 0x01, 0x30, 0x0d };
		DWORD startupBufWrite = 0;
		LPOVERLAPPED ol = (LPOVERLAPPED)malloc(sizeof(OVERLAPPED));
		memset(ol, 0, sizeof(OVERLAPPED));
		WriteFile(port, startupBuf, 3, &startupBufWrite, ol);
		printf("written %d startup bytes\n", startupBufWrite);
	}*/

	DWORD times = 0;

	for (;;)
	{
		// Probably quite bad...
		DWORD bytesRead = 0;
		memset(fileBuf, 0, 32);

		BOOL rfResult = ReadFile(port, fileBuf, 32, &bytesRead, NULL);

		if (rfResult)
		{
			if (memcmp(fileBuf, CMD_RESET, 3) ||
				memcmp(fileBuf, CMD_DIAGNOSTICS, 4))
			{
				mt6WritePort(port, OK_RESPONSE, 3);
			}
		}

		Sleep(16);
	}
}

void mt6SerialTouchInit()
{
	puts("testing outside thread");
	
	touchDevice = CreateFileA("\\\\.\\COM11",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (touchDevice == INVALID_HANDLE_VALUE)
	{
		puts("oh no");
		return;
	}

	SetupComm(touchDevice, 32, 32);

	// Set the comm timeouts
	COMMTIMEOUTS timeouts;
	memset(&timeouts, 0, sizeof(COMMTIMEOUTS));
	timeouts.ReadIntervalTimeout = MAXDWORD;
	timeouts.ReadTotalTimeoutConstant = 8;
	timeouts.ReadTotalTimeoutMultiplier = 0;
	timeouts.WriteTotalTimeoutConstant = 16;
	timeouts.WriteTotalTimeoutMultiplier = 1;
	SetCommTimeouts(touchDevice, &timeouts);

	CreateThread(NULL, 0, mt6SerialTouchThread, touchDevice, 0, NULL);
}