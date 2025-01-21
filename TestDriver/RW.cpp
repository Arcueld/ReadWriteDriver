#include <intrin.h>
#include "RW.h"
#include "Search.h"

PVOID MDLMapMemory(OUT PMDL* mdl,PVOID TargetAddr,SIZE_T size,MODE previousMode) {
	PMDL pMdl = IoAllocateMdl(TargetAddr,size,FALSE,FALSE,NULL);
	PVOID mapAddr = NULL;
	if (!pMdl) {
	
		return NULL;
	}
	BOOLEAN isLocked = FALSE;
	__try {
		MmProbeAndLockPages(pMdl, previousMode, IoReadAccess);
		isLocked = TRUE;
		// MmMapLockedPages // if faied BSOD so use MmMapLockedPagesSpecifyCache avoid BSOD
		mapAddr = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		if (isLocked) {
			MmUnlockPages(pMdl);
		}
		IoFreeMdl(pMdl);
		return NULL;
	}

	*mdl = pMdl;
	return mapAddr;

}
void MDLUnMapMemory(PMDL mdl,PVOID mapAddr) {

	BOOLEAN isLocked = FALSE;
	__try {
		MmUnmapLockedPages(mapAddr, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return;
	}
	return;
}
NTSTATUS ReadMemory1(HANDLE Pid,PVOID TargetAddr, PVOID buffer, SIZE_T size) {
	if ((ULONG_PTR)TargetAddr >= (ULONG_PTR)MmHighestUserAddress
		|| ((ULONG64)TargetAddr + size) >= (ULONG_PTR)MmHighestUserAddress
		|| ((ULONG64)TargetAddr + size) < (ULONG_PTR)TargetAddr) {
		return STATUS_ACCESS_VIOLATION;
	}
	if (!buffer) {
		return STATUS_INVALID_PARAMETER_3;
	}
	PEPROCESS pEprocess = NULL;
	KAPC_STATE apcState = { 0 };
	NTSTATUS status = PsLookupProcessByProcessId(Pid, &pEprocess);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	if (PsGetProcessExitStatus(pEprocess) != 0x103) {
		ObDereferenceObject(pEprocess);
		return STATUS_INVALID_PARAMETER_1;
	}

	status = STATUS_UNSUCCESSFUL;

	PVOID pMem = ExAllocatePool(NonPagedPool, size);
	memset(pMem, 0, size);

	KeStackAttachProcess(pEprocess, &apcState);
	
	if (MmIsAddressValid(TargetAddr) && MmIsAddressValid((PVOID)((ULONG64)TargetAddr + size - 1))) {
		memcpy(pMem, TargetAddr, size);
		status = STATUS_SUCCESS;
	}

	KeUnstackDetachProcess(&apcState);

	if (NT_SUCCESS(status)) {
		memcpy(buffer, pMem, size);
	}
	ObDereferenceObject(pEprocess);
	ExFreePool(pMem);

	return status;

}

NTSTATUS ReadMemory2(HANDLE Pid, PVOID TargetAddr, PVOID buffer, SIZE_T size) {
	if ((ULONG_PTR)TargetAddr >= (ULONG_PTR)MmHighestUserAddress
		|| ((ULONG64)TargetAddr + size) >= (ULONG_PTR)MmHighestUserAddress
		|| ((ULONG64)TargetAddr + size) < (ULONG_PTR)TargetAddr) {
		return STATUS_ACCESS_VIOLATION;
	}
	if (!buffer) {
		return STATUS_INVALID_PARAMETER_3;
	}
	PEPROCESS pEprocess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(Pid, &pEprocess);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	if (PsGetProcessExitStatus(pEprocess) != 0x103) {
		ObDereferenceObject(pEprocess);
		return STATUS_INVALID_PARAMETER_1;
	}

	status = STATUS_UNSUCCESSFUL;

	SIZE_T pro = 0;
	status = MmCopyVirtualMemory(pEprocess, TargetAddr, IoGetCurrentProcess(), buffer, size, UserMode, &pro);
	ObDereferenceObject(pEprocess);

	return status;
}

NTSTATUS ReadMemory3(HANDLE Pid, PVOID TargetAddr, PVOID buffer, SIZE_T size) {
	if ((ULONG_PTR)TargetAddr >= (ULONG_PTR)MmHighestUserAddress
		|| ((ULONG64)TargetAddr + size) >= (ULONG_PTR)MmHighestUserAddress
		|| ((ULONG64)TargetAddr + size) < (ULONG_PTR)TargetAddr) {
		return STATUS_ACCESS_VIOLATION;
	}
	if (!buffer) {
		return STATUS_INVALID_PARAMETER_3;
	}
	
	PEPROCESS pEprocess = NULL;
	KAPC_STATE apcState = { 0 };
	NTSTATUS status = PsLookupProcessByProcessId(Pid, &pEprocess);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	if (PsGetProcessExitStatus(pEprocess) != 0x103) {
		ObDereferenceObject(pEprocess);
		return STATUS_INVALID_PARAMETER_1;
	}

	status = STATUS_UNSUCCESSFUL;

	PVOID pMem = ExAllocatePool(NonPagedPool, size);
	memset(pMem, 0, size);

	KeStackAttachProcess(pEprocess, &apcState);
	if (MmIsAddressValid(TargetAddr) && MmIsAddressValid((PVOID)((ULONG64)TargetAddr + size - 1))) {
		PMDL mdl = NULL;
		PVOID mapAddr = MDLMapMemory(&mdl, TargetAddr, size, UserMode);
		
		if (mapAddr) {

			memcpy(pMem, mapAddr, size);
			MDLUnMapMemory(mdl, mapAddr);
		}
		status = STATUS_SUCCESS;
	}
	KeUnstackDetachProcess(&apcState);

	if (NT_SUCCESS(status)) {
		memcpy(buffer, pMem, size);
	}

	ObDereferenceObject(pEprocess);

	return status;
}

NTSTATUS ReadMemory4(HANDLE Pid, PVOID TargetAddr, PVOID buffer, SIZE_T size) {
	if ((ULONG_PTR)TargetAddr >= (ULONG_PTR)MmHighestUserAddress
		|| ((ULONG64)TargetAddr + size) >= (ULONG_PTR)MmHighestUserAddress
		|| ((ULONG64)TargetAddr + size) < (ULONG_PTR)TargetAddr) {
		return STATUS_ACCESS_VIOLATION;
	}
	if (!buffer) {
		return STATUS_INVALID_PARAMETER_3;
	}
	PEPROCESS pEprocess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(Pid, &pEprocess);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	if (PsGetProcessExitStatus(pEprocess) != 0x103) {
		ObDereferenceObject(pEprocess);
		return STATUS_INVALID_PARAMETER_1;
	}

	status = STATUS_UNSUCCESSFUL;

	PVOID pMem = ExAllocatePool(NonPagedPool, size);
	memset(pMem, 0, size);

	ULONG64 newCr3 = *(PULONG64) ((PUCHAR)pEprocess + 0x28);
	ULONG64 oldCr3 = __readcr3();


	KeEnterCriticalRegion();
	_disable();

	__writecr3(newCr3);

	if (MmIsAddressValid(TargetAddr) && MmIsAddressValid((PVOID)((ULONG64)TargetAddr + size - 1))) {
		memcpy(pMem, TargetAddr, size);
		status = STATUS_SUCCESS;
	}
	_enable();

	__writecr3(oldCr3);

	KeLeaveCriticalRegion();

	if (NT_SUCCESS(status)) {
		memcpy(buffer, pMem, size);
	}


	ObDereferenceObject(pEprocess);
	ExFreePool(pMem);

	return status;

}


NTSTATUS WriteMemory1(HANDLE Pid, PVOID TargetAddr, PVOID buffer, SIZE_T size) {
	if ((ULONG_PTR)TargetAddr >= (ULONG_PTR)MmHighestUserAddress
		|| ((ULONG64)TargetAddr + size) >= (ULONG_PTR)MmHighestUserAddress
		|| ((ULONG64)TargetAddr + size) < (ULONG_PTR)TargetAddr) {
		return STATUS_ACCESS_VIOLATION;
	}
	if (!buffer) {
		return STATUS_INVALID_PARAMETER_3;
	}
	PEPROCESS pEprocess = NULL;
	KAPC_STATE apcState = { 0 };
	NTSTATUS status = PsLookupProcessByProcessId(Pid, &pEprocess);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	if (PsGetProcessExitStatus(pEprocess) != 0x103) {
		ObDereferenceObject(pEprocess);
		return STATUS_INVALID_PARAMETER_1;
	}

	SIZE_T retSize = 0;
	status = MmCopyVirtualMemory(IoGetCurrentProcess(), buffer, pEprocess, TargetAddr, size, UserMode, &retSize);
	if (NT_SUCCESS(status)) {
		ObDereferenceObject(pEprocess);
		return status;
	}




	status = STATUS_UNSUCCESSFUL;

	PVOID pMem = ExAllocatePool(NonPagedPool, size);
	memset(pMem, 0, size);

	KeStackAttachProcess(pEprocess, &apcState);

	if (MmIsAddressValid(TargetAddr) && MmIsAddressValid((PVOID)((ULONG64)TargetAddr + size - 1))) {
		memcpy(pMem, TargetAddr, size);
		status = STATUS_SUCCESS;
	}

	KeUnstackDetachProcess(&apcState);

	if (NT_SUCCESS(status)) {
		memcpy(buffer, pMem, size);
	}
	ObDereferenceObject(pEprocess);
	ExFreePool(pMem);

	return status;

}
