#pragma once
#include <ntifs.h>


EXTERN_C NTSTATUS ReadMemory1(HANDLE Pid, PVOID TargetAddr, PVOID buffer, SIZE_T size);
EXTERN_C NTSTATUS ReadMemory2(HANDLE Pid, PVOID TargetAddr, PVOID buffer, SIZE_T size);
EXTERN_C NTSTATUS ReadMemory3(HANDLE Pid, PVOID TargetAddr, PVOID buffer, SIZE_T size);
EXTERN_C NTSTATUS ReadMemory4(HANDLE Pid, PVOID TargetAddr, PVOID buffer, SIZE_T size);
EXTERN_C NTSTATUS WriteMemory1(HANDLE Pid, PVOID TargetAddr, PVOID buffer, SIZE_T size);