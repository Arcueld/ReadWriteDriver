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
    CMD_QUERY_MEM,
    CMD_PROTECT_PROCESS,
    CMD_REMOTE_CALL
}CMD;

typedef enum _ProtectState {
    PROTECT_ENABLE,
    PROTECT_DISABLE
}ProtectState;

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

typedef struct _ProtectInfo
{
    ULONG64 pid;
    ProtectState state;
    
}ProtectInfo, * PProtectInfo;

typedef struct _RemoteCallInfo
{
    ULONG64 pid;
    ULONG64 shellcode;
    ULONG64 shellcodeSize;

}RemoteCallInfo, * PRemoteCallInfo;

