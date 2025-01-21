#include "Module.h"

// get Ring3 Moudle By Traversal InLoadOrderLinks
ULONG_PTR GetModuleX32(PEPROCESS pEprocess,PPEB32 peb,PUNICODE_STRING moduleName, PULONG_PTR sizeImage) {



	PPEB_LDR_DATA32 ldr = (PPEB_LDR_DATA32)ULongToPtr(peb->Ldr);
	PLIST_ENTRY32 moduleList = (PLIST_ENTRY32)&ldr->InLoadOrderModuleList;
	PLIST_ENTRY32 currentEnty = moduleList->Flink;
	while (currentEnty!= moduleList)
	{
		PLDR_DATA_TABLE_ENTRY32 entry = (PLDR_DATA_TABLE_ENTRY32)ULongToPtr(currentEnty);
		UNICODE_STRING unicodeString;
		unicodeString.Length = entry->BaseDllName.Length;
		unicodeString.MaximumLength = entry->BaseDllName.MaximumLength;
		unicodeString.Buffer = (PWSTR)ULongToPtr(entry->BaseDllName.Buffer);

		if (RtlCompareUnicodeString(moduleName, &unicodeString, TRUE) == 0) {
			if (sizeImage) *sizeImage = entry->SizeOfImage;
			
			return entry->DllBase;
		}


		currentEnty = currentEnty->Flink;
	}

	return NULL;
}
ULONG_PTR GetModuleX64(PEPROCESS pEprocess, PPEB64 peb, PUNICODE_STRING moduleName, PULONG_PTR sizeImage) {
	PPEB_LDR_DATA ldr = peb->Ldr;
	PLIST_ENTRY moduleList = (PLIST_ENTRY)&ldr->InLoadOrderModuleList;

	if (!MmIsAddressValid(moduleList)) {
		return NULL;
	}
	PLIST_ENTRY currentEnty = moduleList->Flink;
	while (currentEnty != moduleList)
	{
		PLDR_DATA_TABLE_ENTRY64 entry = (PLDR_DATA_TABLE_ENTRY64)currentEnty;
		if (RtlCompareUnicodeString(moduleName, &entry->BaseDllName, TRUE) == 0) {
			if (sizeImage) *sizeImage = entry->SizeOfImage;
			return entry->DllBase;
		}


		currentEnty = currentEnty->Flink;
	}

	return NULL;
}
ULONG_PTR GetModuleR3(HANDLE Pid,char* ModuleName,PULONG_PTR sizeImage) {

	if (!ModuleName) {
		return NULL;
	}

	pEPROCESS pEprocess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(Pid, &pEprocess);
	
	KAPC_STATE kapcState = { 0 };
	if (!NT_SUCCESS(status)) {
		DbgPrint("get Process Failed [+]: 0x%x\n", status);

		return NULL;
	}

	STRING aModuleName = { 0 };
	RtlInitString(&aModuleName, ModuleName);
	UNICODE_STRING uModuleName = { 0 };
	status = RtlAnsiStringToUnicodeString(&uModuleName, &aModuleName, TRUE);

	if (!NT_SUCCESS(status)) {
		return NULL;
	}

	ULONG_PTR retModule = NULL;
	_wcsupr(uModuleName.Buffer);
	
	KeStackAttachProcess(pEprocess, &kapcState);
	
	PPEB32 peb32 = (PPEB32)PsGetProcessWow64Process(pEprocess);
	SIZE_T retSize = NULL;

	if (peb32) {
		MmCopyVirtualMemory(pEprocess, peb32, pEprocess, peb32, 1, UserMode, &retSize);
		retModule = GetModuleX32(pEprocess, peb32, &uModuleName, sizeImage);
	}
	else {
		PPEB64 peb64 = (PPEB64)PsGetProcessPeb(pEprocess);	
		MmCopyVirtualMemory(pEprocess, peb64, pEprocess, peb64, 1, UserMode, &retSize);
		retModule = GetModuleX64(pEprocess, peb64, &uModuleName, sizeImage);
	}


	KeUnstackDetachProcess(&kapcState);

	return retModule;
}