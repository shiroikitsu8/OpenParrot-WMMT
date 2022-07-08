#pragma once
#include <Windows.h>

static HANDLE touchDevice;

void mt6SetTouchParams(unsigned short x, unsigned short y, BOOL down);
void mt6SerialTouchInit();
