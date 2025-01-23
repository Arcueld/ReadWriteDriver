#pragma once

#ifdef KERNEL
#include <ntifs.h>
#else
#include <Windows.h>
#endif 


typedef struct _CommPackage{
    ULONG64 Id;
    ULONG64 Cmd;
    ULONG64 Data;
    ULONG64 Size;
    ULONG64 StatusCode;
}CommPackage, * PCommPackage;

typedef enum _CMD {
    CMD_TEST,
    CMD_GETMODULE,
    CMD_READ,
    CMD_WRITE,
    CMD_QUERY_MEM
}CMD;

typedef struct _ModuleInfo {
    ULONG64 Pid;
    ULONG64 ModuleName;
    ULONG64 Module;
    ULONG64 ModuleSize;
}ModuleInfo, * PModuleInfo;

typedef struct _ReadWriteInfo
{
    ULONG64 pid;
    ULONG64 BaseAddress;
    ULONG64 Buffer;
    ULONG64 size;
}ReadWriteInfo, * PReadWriteInfo;

typedef struct _QueryMemInfo
{
    ULONG64 pid;
    ULONG64 BaseAddress;
    MEMORY_BASIC_INFORMATION memInfo;
}QueryMemInfo, * PQueryMemInfo;