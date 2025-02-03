#include "FarCall.h"
#include "Search.h"
#include "Module.h"


NTSTATUS
NTAPI
ZwGetNextThreadProc(
    __in HANDLE ProcessHandle,
    __in HANDLE ThreadHandle,
    __in ACCESS_MASK DesiredAccess,
    __in ULONG HandleAttributes,
    __in ULONG Flags,
    __out PHANDLE NewThreadHandle
) {
    static pNtGetNextThread NtGetNextThread = NULL;

    if (!NtGetNextThread) {
        UNICODE_STRING uName = { 0 };
        RtlInitUnicodeString(&uName, L"ZwGetNextThread");
        NtGetNextThread = MmGetSystemRoutineAddress(&uName);
        if (!NtGetNextThread) {
            UNICODE_STRING uName2 = { 0 };
            RtlInitUnicodeString(&uName, L"ZwGetNotificationResourceManager");
            PUCHAR ZwGetNotificationResourceManagerAddr = MmGetSystemRoutineAddress(&uName);
            ZwGetNotificationResourceManagerAddr -= 0x50;
            for (int i = 0; i < 0x30; i++) {
                if (ZwGetNotificationResourceManagerAddr[i] == 0x48 && ZwGetNotificationResourceManagerAddr[i + 1] == 0x8B && ZwGetNotificationResourceManagerAddr[i + 2] == 0xC4) {
                    NtGetNextThread = (pNtGetNextThread)(ZwGetNotificationResourceManagerAddr + i);
                    break;
                }
            }
            
        }
    }
    if (NtGetNextThread) {
        return NtGetNextThread(ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags, NewThreadHandle);
    }
    else
    {
        return STATUS_UNSUCCESSFUL;
    }
}
void KernelSleep(ULONG64 ms, BOOLEAN alertable) {
    LARGE_INTEGER inTime;
    inTime.QuadPart = ms * -10000;
    KeDelayExecutionThread(KernelMode, alertable, &inTime);
}
PETHREAD getProcessMainThread(PEPROCESS process) {
    PETHREAD ethread = NULL;
    HANDLE hThread = NULL;
    KAPC_STATE apcState = { 0 };
    KeStackAttachProcess(process, &apcState);
    NTSTATUS status = ZwGetNextThreadProc(NtCurrentProcess(), NULL, THREAD_ALL_ACCESS, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, &hThread);
    if (NT_SUCCESS(status)) {
        status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &ethread, NULL);
        NtClose(hThread);
        if (!NT_SUCCESS(status)) {
            ethread = NULL;
        }
    }
    KeUnstackDetachProcess(&apcState);
    return ethread;
}


NTSTATUS
PsSuspendThread(
    IN PETHREAD Thread,
    OUT PULONG PreviousSuspendCount OPTIONAL
) {
    static pPsSuspendThread PsSuspendThreadProc = NULL;

    if (!PsSuspendThreadProc) {
        PsSuspendThreadProc = (pPsSuspendThread)searchCode("ntoskrnl.exe", "PAGE", "4C8BF2488BF98364***65", -0x15);
    }
    if (PsSuspendThreadProc) {
        return PsSuspendThreadProc(Thread, PreviousSuspendCount);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
PsResumeThread(
    IN PETHREAD Thread,
    OUT PULONG PreviousSuspendCount OPTIONAL
) {
    static pPsResumeThread PsResumeThreadProc = NULL;

    if (!PsResumeThreadProc) {
        PsResumeThreadProc = (pPsResumeThread)searchCode("ntoskrnl.exe", "PAGE", "488BDA488BF9E8****65", -0xf);
    }
    if (PsResumeThreadProc) {
        PsResumeThreadProc(Thread, PreviousSuspendCount);
    }
    return STATUS_UNSUCCESSFUL;

}

VOID
ExFreeMemWorkItem(
    _In_ PVOID Parameter
) {
    PFreeMemStuct freeMemStuct = (PFreeMemStuct)Parameter;
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(freeMemStuct->pid, &process);


    if (!NT_SUCCESS(status)) return;
    if (PsGetProcessExitStatus(process) != 0x103) {
        ObDereferenceObject(process);
        return;
    }
    ULONG64 exeValue=0;
    SIZE_T copyNum = 0;
    BOOLEAN isSuccess = FALSE;

    int count = 0;
    while (1){
        if (count > 1000) break;

        NTSTATUS status = MmCopyVirtualMemory(process, freeMemStuct->isExecuteAddr, IoGetCurrentProcess(), &exeValue, 8, KernelMode, &copyNum);

        if (NT_SUCCESS(status) && exeValue == 1) {
            isSuccess = TRUE;
            break;
        }        
        KernelSleep(100, FALSE);
        count++;
    }

    KAPC_STATE apcState = { 0 };
    KeStackAttachProcess(process, &apcState);
    if (isSuccess) {
        PVOID lpMem = (PVOID)(freeMemStuct->isExecuteAddr - 0x500);
        ZwFreeVirtualMemory(NtCurrentProcess(), &lpMem, &freeMemStuct->freeSize, MEM_RELEASE);
    }

    KeUnstackDetachProcess(&apcState);

    ExFreePool(freeMemStuct);
    ObDereferenceObject(process);

}
NTSTATUS RemoteCall(HANDLE pid, PVOID shellcode, ULONG64 shellcodeSize) {

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &process);

    if (!NT_SUCCESS(status)) return status;
    if (PsGetProcessExitStatus(process) != 0x103) {
        ObDereferenceObject(process);
        return STATUS_UNSUCCESSFUL;
    }

    PETHREAD ethread = getProcessMainThread(process);

    if (!ethread) return status;

    status = PsSuspendThread(ethread, NULL);

    if (NT_SUCCESS(status)) {
        PUCHAR peb32 = PsGetProcessWow64Process(process);


        ObDereferenceObject(process);

        ULONG64 kShellcode = ExAllocatePool(PagedPool, shellcodeSize);
        memcpy(kShellcode, shellcode, shellcodeSize);


        KAPC_STATE apcState = { 0 };
        KeStackAttachProcess(process, &apcState);
        PUCHAR lpMem = NULL;
        SIZE_T size = shellcodeSize + PAGE_SIZE;
        do {
            status = ZwAllocateVirtualMemory(NtCurrentProcess(), &lpMem, NULL, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!NT_SUCCESS(status)) {
                break;
            }       

            memset(lpMem, 0, shellcodeSize);

            PUCHAR ShellMem = lpMem + PAGE_SIZE;
            memcpy(ShellMem, kShellcode, shellcodeSize);


            BOOLEAN isWoW64 = peb32 ? 1 : 0;
            if (isWoW64) {

                char bufcode[] = {
                    0x60,
                    0xB8,0x78,0x56,0x34,0x12,
                    0x83,0xEC,0x40,
                    0xFF,0xD0,
                    0x83,0xC4,0x40,
                    0xB8,0x78,0x56,0x34,0x12,
                    0xC7,0x00,0x01,0x00,0x00,0x00,
                    0x61,
                    0xFF,0x25,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00
                };


                ULONG_PTR teb = PsGetThreadTeb(ethread);
                ULONG_PTR WoWContext = *(ULONG_PTR*)(teb + 0x1488);

                *(PULONG)&bufcode[2] = (ULONG)ShellMem;
                *(PULONG)&bufcode[15] = (ULONG)lpMem+0x500;
                *(PULONG)&bufcode[32] = *(ULONG_PTR*)(WoWContext + 0xbc);

                memcpy(lpMem, bufcode, sizeof(bufcode));
                *(ULONG_PTR*)(WoWContext + 0xbc) = lpMem;

            }
            else {
                ULONG_PTR InitialStack = *(ULONG_PTR*)((ULONG_PTR)ethread + 0x28);
                PKTRAP_FRAME trapFrame = (PKTRAP_FRAME)((ULONG_PTR)InitialStack - sizeof(KTRAP_FRAME));
                /*
                                     push rax
                                     push rcx
                                     push rdx
                                     push rbx
                                     push rbp
                                     push rsi
                                     push rdi
                                     push r8
                                     push r9
                                     push r10
                                     push r11
                                     push r12
                                     push r13
                                     push r14
                                     push r15
                                     mov rax,123456789
                                     sub rsp,A8
                                     call rax
                                     add rsp,A8
                                     pop r15
                                     pop r14
                                     pop r13
                                     pop r12
                                     pop r11
                                     pop r10
                                     pop r9
                                     pop r8
                                     pop rdi
                                     pop rsi
                                     pop rbp
                                     pop rbx
                                     pop rdx
                                     pop rcx
                                     mov rax,123456789
                                     mov qword ptr ds:[rax],1
                                     pop rax
                                     jmp qword ptr ds:[7FFD7E9FCA49]
                                     add byte ptr ds:[rax],al
                                     add byte ptr ds:[rax],al
                                     add byte ptr ds:[rax],al
                                     add byte ptr ds:[rax],al                  */
                char bufcode[] = {
                    0x50,
                    0x51,
                    0x52,
                    0x53,
                    0x55,
                    0x56,
                    0x57,
                    0x41,0x50,
                    0x41,0x51,
                    0x41,0x52,
                    0x41,0x53,
                    0x41,0x54,
                    0x41,0x55,
                    0x41,0x56,
                    0x41,0x57,
                    0x48,0xB8,0x89,0x67,0x45,0x23,0x01,0x00,0x00,0x00,
                    0x48,0x81,0xEC,0xA0,0x00,0x00,0x00,
                    0xFF,0xD0,
                    0x48,0x81,0xC4,0xA0,0x00,0x00,0x00,
                    0x41,0x5F,
                    0x41,0x5E,
                    0x41,0x5D,
                    0x41,0x5C,
                    0x41,0x5B,
                    0x41,0x5A,
                    0x41,0x59,
                    0x41,0x58,
                    0x5F,
                    0x5E,
                    0x5D,
                    0x5B,
                    0x5A,
                    0x59,
                    0x48,0xB8,0x89,0x67,0x45,0x23,0x01,0x00,0x00,0x00,
                    0x48,0xC7,0x00,0x01,0x00,0x00,0x00,0x58,
                    0xFF,0x25,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                };
                *(PULONG64)&bufcode[25] = (ULONG64)ShellMem;
                *(PULONG64)&bufcode[73] = (ULONG64)lpMem + 0x500;
                *(PULONG64)&bufcode[95] = trapFrame->Rip;

                memcpy(lpMem, bufcode, sizeof(bufcode));
                trapFrame->Rip = lpMem;

            }
            PFreeMemStuct freeMemStuct = ExAllocatePool(NonPagedPool, sizeof(FreeMemStuct));
            freeMemStuct->pid = pid;
            freeMemStuct->isExecuteAddr = lpMem + 0x500;
            freeMemStuct->freeSize = size;
            ExInitializeWorkItem(&freeMemStuct->queueItem, ExFreeMemWorkItem, freeMemStuct);
            ExQueueWorkItem(&freeMemStuct->queueItem, DelayedWorkQueue);
            
            PsResumeThread(ethread, NULL);
            ObDereferenceObject(ethread);

        } while (0);
        KeUnstackDetachProcess(&apcState);

        ExFreePool(kShellcode);
    }
    return STATUS_SUCCESS;

}