#ifndef CRYPT000_CRYPTIT_H
#define CRYPT000_CRYPTIT_H

#ifdef _WIN32
#include <Windows.h>
#include "detours.h"
#ifndef _DEBUG
#pragma comment(lib, "detours.lib")
#else
#pragma comment(lib, "detoursd.lib")
#endif
#elif _LINUX
#include <>
#endif

void InstallCrypt();

void SetSockToXList(int s);
void DeleteSockFromXList(int s);

#endif
