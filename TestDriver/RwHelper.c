#include "RwHelper.h"


NTSTATUS(NTAPI NtProtectVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection
    ) {
    static pNtProtectVirtualMemory ZwProtectVirtualMemory = NULL;
    if (!ZwProtectVirtualMemory) {
        UNICODE_STRING uName = { 0 };
        RtlInitUnicodeString(&uName, "ZwIsProcessInJob");
        PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&uName);
        if (func) {
            func += 20;
            for (int i = 0; i <= 100; i++) {
                if (func[i] == 0x48 && func[i + 1] == 0x8b && func[i + 2] == 0xc4) {
                    ZwProtectVirtualMemory = (pNtProtectVirtualMemory)(func + i);
                    break;
                }
            }
        }
    }

    if (ZwProtectVirtualMemory) {
        return ZwProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection);
    }

    return STATUS_NOT_IMPLEMENTED;

}


void EnableCR0WriteProtection(KIRQL irql)
{
    UINT64 cr0 = __readcr0();
    cr0 |= 0x10000;
    _enable();
    __writecr0(cr0);
    KeLowerIrql(irql);
}



KIRQL DisableCR0WriteProtection()
{
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    UINT64 cr0 = __readcr0();
    cr0 &= 0xfffffffffffeffff;
    __writecr0(cr0);
    _disable();
    return irql;

}