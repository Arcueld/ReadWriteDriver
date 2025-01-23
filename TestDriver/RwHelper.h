#pragma once
#include <ntifs.h>

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection
    );

EXTERN_C NTSTATUS(NTAPI NtProtectVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection
    );

EXTERN_C void EnableCR0WriteProtection();
EXTERN_C void DisableCR0WriteProtection();