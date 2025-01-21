#include "Comm.h"
#include "Search.h"


FileCallBack oldExpDisQueryAttributeInformation = NULL;
FileCallBack oldExpDisSetAttributeInformation = NULL;
CommCallBackProc g_commRoutine = NULL;
PULONG64 g_Win7Callback = NULL;
PULONG64 g_Win10Callback = NULL;
FileCallBackWin10 oldWin10Func = NULL;



NTSTATUS QueryFileRoutine(HANDLE FileHandle ,PVOID info, PVOID un1, PVOID un2) {

	if (MmIsAddressValid(info)) {
		PCommPackage package = (PCommPackage)info;
		if(package->Id == 0x114514){
			package->StatusCode = g_commRoutine(package);
		}
		else
		{
			if (oldExpDisQueryAttributeInformation) {
				return oldExpDisQueryAttributeInformation(FileHandle, info, un1,un2);
			}
		}

	}
	
	return STATUS_SUCCESS;
}

NTSTATUS SetFileRoutine(HANDLE FileHandle, PVOID info, PVOID un1, PVOID un2) {
	if (MmIsAddressValid(info)) {
		PCommPackage package = (PCommPackage)info;
		if (package->Id == 0x114514) {
			package->StatusCode = g_commRoutine(package);
		}
		else
		{
			if (oldExpDisSetAttributeInformation) {
				return oldExpDisSetAttributeInformation(FileHandle, info, un1, un2);
			}
		}

	}

	return STATUS_SUCCESS;
}

NTSTATUS RegisterWin7(CommCallBackProc commRoutine) {
	UNICODE_STRING funcName = { 0 };
	
	RtlInitUnicodeString(&funcName, L"ExRegisterAttributeInformationCallback");
	PUCHAR pFunc =  MmGetSystemRoutineAddress(&funcName);
	ULONG64 offset = *(PLONG)(pFunc + 0xd + 0x3);
	PULONG64 ExpDisQueryAttributeInformation = (PULONG64)(pFunc + 0xd + 0x7 + offset);
	oldExpDisQueryAttributeInformation = (FileCallBack)ExpDisQueryAttributeInformation[0];
	oldExpDisSetAttributeInformation = (FileCallBack)ExpDisQueryAttributeInformation[1];
	ExpDisQueryAttributeInformation[0] = 0;
	ExpDisQueryAttributeInformation[1] = 0;
	
	pExRegisterAttributeInformationCallback ExRegisterAttributeInformationCallback = (pExRegisterAttributeInformationCallback)pFunc;
	EX_ATTRIBUTE_INFORMATION_REGISTRATION registration = { 0 }; 
	registration.QueryRoutine = QueryFileRoutine;
	registration.SetRoutine = SetFileRoutine;
	
	NTSTATUS status = ExRegisterAttributeInformationCallback(&registration);
	if (NT_SUCCESS(status)) {
		g_Win7Callback = ExpDisQueryAttributeInformation;
		g_commRoutine = commRoutine;
	}

	return status;
}
NTSTATUS UnRegisterWin7() {
	if (g_Win7Callback) {
		g_Win7Callback[0] = oldExpDisQueryAttributeInformation;
		g_Win7Callback[1] = oldExpDisSetAttributeInformation;
		g_Win7Callback = NULL;
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}




NTSTATUS Win10Routine(PVOID info, PVOID un1, PVOID un2) {

	if (MmIsAddressValid(info)) {
		PCommPackage package = (PCommPackage)info;
		if (package->Id == 0x114514) {
			package->StatusCode = g_commRoutine(package);
		}
		else
		{
			if (oldWin10Func) {
				return oldWin10Func(info, un1, un2);
			}
		}

	}

	return STATUS_SUCCESS;
}


NTSTATUS RegisterWin10(CommCallBackProc commRoutine) {
	ULONG_PTR addr = searchCode("ntoskrnl.exe", "PAGE", "488B05****75*488B05****E8", 0);
	if (addr) {

		ULONG64 offset = *(PLONG)(addr + 0x3);

		PULONG64 table = (PULONG64)(addr + 0x7 + offset);


		if (MmIsAddressValid(table)) {
			g_Win10Callback = table;
			oldWin10Func = table[0];
			table[0] = Win10Routine;
			g_commRoutine = commRoutine;
			return STATUS_SUCCESS;
		}

	}
	return STATUS_UNSUCCESSFUL;
}
NTSTATUS UnRegisterWin10() {
	DbgPrintEx(77, 0, "unRegWin10\n");
	if (g_Win10Callback) {
		g_Win10Callback[0] = oldWin10Func;
		g_Win10Callback = NULL;

		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS RegisterComm(CommCallBackProc commRoutine) {
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion(&version);

	if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601) {
		DbgPrintEx(77, 0, "egisterWin7\n");

		return RegisterWin7(commRoutine);
	}
	DbgPrintEx(77, 0, "RegisterWin10\n");

	return RegisterWin10(commRoutine);


}
NTSTATUS UnRegisterComm() {
	RTL_OSVERSIONINFOEXW version = { 0 };
	RtlGetVersion(&version);

	if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601) {
		DbgPrint("UnRegisterWin7\n");
		return UnRegisterWin7();
	}

	return UnRegisterWin10();
}