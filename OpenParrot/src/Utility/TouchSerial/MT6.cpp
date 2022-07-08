#include "MT6.h"
#include <vector>

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

static volatile BOOL bHasBooted = false;

static volatile unsigned short touchx = 0;
static volatile unsigned short touchy = 0;
static volatile BOOL touchpressed = FALSE;
static volatile BOOL touchlift = FALSE;

void mt6SetTouchParams(unsigned short x, unsigned short y, BOOL down)
{
	if (bHasBooted)
	{
		touchx = x;
		touchy = y;
		touchpressed = down;
	}
}

DWORD mt6WritePort(HANDLE port, char data[], unsigned length)
{
	DWORD numWritten = 0;
	WriteFile(port, data, length, &numWritten, NULL);
	//FlushFileBuffers(port);
	return numWritten;
}

DWORD mt6SerialTouchThread(HANDLE port)
{
	char fileBuf[32];
	puts("starting serial touch thread");

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
		if (times++ % 100 == 0)
		{
			puts("still going");
		}

		// Probably quite bad...
		DWORD bytesRead = 0;
		memset(fileBuf, 0, 32);

		BOOL rfResult = ReadFile(port, fileBuf, 32, &bytesRead, NULL);

		if (rfResult)
		{
			BOOL packetRecognised = FALSE;
			if (memcmp(fileBuf, CMD_RESET, 3))
			{
				bHasBooted = false;
				packetRecognised = TRUE;
				mt6WritePort(port, OK_RESPONSE, 3);
			}

			if (memcmp(fileBuf, CMD_DIAGNOSTICS, 4))
			{
				bHasBooted = true;
				packetRecognised = TRUE;
				mt6WritePort(port, OK_RESPONSE, 3);
			}

			if (!packetRecognised)
			{
				puts("unknown packet, responding with OK");
				mt6WritePort(port, OK_RESPONSE, 3);
			}
		}

		if (touchpressed)
		{
			touchlift = TRUE;
			char touchResp[5];
			memset(touchResp, 0, 5);
			touchResp[0] = (char)0b11000000;
			touchResp[1] = (touchx & 0b01111111);
			touchResp[2] = ((touchx >> 8) & 0b01111111);
			touchResp[3] = (touchy & 0b01111111);
			touchResp[4] = ((touchy >> 8) & 0b01111111);
			mt6WritePort(port, touchResp, 5);
		}
		else
		{
			if (touchlift)
			{
				char touchResp[5];
				memset(touchResp, 0, 5);
				touchResp[0] = (char)0b10000000;
				touchResp[1] = (touchx & 0b01111111);
				touchResp[2] = ((touchx >> 8) & 0b01111111);
				touchResp[3] = (touchy & 0b01111111);
				touchResp[4] = ((touchy >> 8) & 0b01111111);
				mt6WritePort(port, touchResp, 5);
				touchlift = false;
			}
		}

		Sleep(16);
	}
}

void mt6SerialTouchInit()
{
	puts("initialising 3m microtouch emulator on com11");
	
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