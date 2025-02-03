#pragma once
#include <ntifs.h>

typedef NTSTATUS(NTAPI* pNtGetNextThread)(
    __in HANDLE ProcessHandle,
    __in HANDLE ThreadHandle,
    __in ACCESS_MASK DesiredAccess,
    __in ULONG HandleAttributes,
    __in ULONG Flags,
    __out PHANDLE NewThreadHandle
    );

typedef NTSTATUS (NTAPI* pPsSuspendThread)(
    IN PETHREAD Thread,
    OUT PULONG PreviousSuspendCount OPTIONAL
);

typedef NTSTATUS (NTAPI* pPsResumeThread)(
    IN PETHREAD Thread,
    OUT PULONG PreviousSuspendCount OPTIONAL
);

EXTERN_C PVOID
PsGetThreadTeb(
    __in PETHREAD Thread
);



typedef struct _FreeMemStuct {
    WORK_QUEUE_ITEM queueItem;
    HANDLE pid;
    ULONG64 isExecuteAddr;
    ULONG64 freeSize;

}FreeMemStuct,*PFreeMemStuct;


NTSTATUS RemoteCall(HANDLE pid, PVOID shellcode, ULONG64 shellcodeSize);

