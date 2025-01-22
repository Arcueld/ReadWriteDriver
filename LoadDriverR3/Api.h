#pragma once
#include <Windows.h>


EXTERN_C BOOLEAN WINAPI AR_DriverLoad();
EXTERN_C BOOLEAN WINAPI AR_UnDriverLoad();
EXTERN_C ULONG64 WINAPI AR_GetMoudle(DWORD Pid,char* moduleName);
EXTERN_C BOOLEAN WINAPI AR_ReadMemory(DWORD pid, ULONG64 BaseAddress, PVOID Buffer, ULONG size);
EXTERN_C BOOLEAN WINAPI AR_TestComm();
EXTERN_C BOOLEAN WINAPI AR_WriteMemory(DWORD pid, ULONG64 BaseAddress, PVOID Buffer, ULONG size);