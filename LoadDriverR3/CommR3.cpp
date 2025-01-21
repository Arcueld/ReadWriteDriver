#include "CommR3.h"
#include "defenition.h"
#include "CommStruct.h"

pNtQueryInformationFile NtQueryInformationFile = NULL;
pNtConvertBetweenAuxiliaryCounterAndPerformanceCounter NtConvertBetweenAuxiliaryCounterAndPerformanceCounter = NULL;
HANDLE fileHandle = NULL;

ULONG getVersion() {
	static ULONG buildVersion = 0;
	if (buildVersion) return buildVersion;

#ifdef _WIN64
	PPEB peb = (PPEB)__readgsqword(0x60);
#endif
#ifdef _X86_
	PPEB peb = (PPEB)__readfsdword(0x30);
#endif

	buildVersion = peb->OSBuildNumber;
	return buildVersion;
}
BOOLEAN InitComm() {
HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");

ULONG buildVersion = getVersion();

	if (buildVersion == 7600 || buildVersion == 7601) {
		// win7
		NtQueryInformationFile = (pNtQueryInformationFile)GetProcAddress(hNtDll, "NtQueryInformationFile");
		char temDir[] = { 0 };
		GetTempPathA(MAX_PATH,temDir);
		strcat_s(temDir, "\\1.txt");
		fileHandle = CreateFileA(temDir, FILE_ALL_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!fileHandle) {
			printf("create file failed!\n");
			return FALSE;
		}


	}else{
		// win10
		NtConvertBetweenAuxiliaryCounterAndPerformanceCounter = (pNtConvertBetweenAuxiliaryCounterAndPerformanceCounter)GetProcAddress(hNtDll, "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");
	}
	return TRUE;

}
BOOLEAN CommWin7(ULONG64 cmd, PVOID inData, SIZE_T size) {


	IO_STATUS_BLOCK block = { 0 };
	char buf[0xff] = { 0 };
	PCommPackage package = (PCommPackage)buf;
	package->Id = 0x114514;
	package->Cmd = cmd;
	package->Size = size;
	package->Data = (ULONG64)inData;
	package->StatusCode = -1;

	NTSTATUS status = NtQueryInformationFile(fileHandle, &block, package, sizeof(buf), FileUnusedInformation);
	return package->StatusCode == 0;

}
BOOLEAN CommWin10(ULONG64 cmd, PVOID inData, SIZE_T size) {

	CommPackage package;
	package.Id = 0x114514;
	package.Cmd = cmd;
	package.Size = size;
	package.Data = (ULONG64)inData;
	package.StatusCode = -1;

	ULONG64 xx = NULL;
	PCommPackage data = &package;
	NTSTATUS status = NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(1, (PVOID)&data, (PVOID)&xx, NULL);
	return package.StatusCode == 0;

}
BOOLEAN DriverComm(ULONG64 cmd, PVOID inData, SIZE_T size) {
	if (InitComm()){
		ULONG buildVersion = getVersion();
		if (buildVersion == 7600 || buildVersion == 7601) {
			return CommWin7(cmd, inData, size);
		}else{
			return CommWin10(cmd, inData, size);
		}
	}
	return FALSE;
}

