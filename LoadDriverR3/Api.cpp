#include "CommStruct.h"
#include "CommR3.h"
#include "LoadDriver.h"
#include "Api.h"

LPCWSTR DriverName = getRandomSysServiceName();
LPCWSTR DriverDir = getRandomSysDir();

EXTERN_C BOOLEAN WINAPI AR_TestComm() {

	ULONG64 xx;

	return DriverComm(CMD_TEST, &xx, sizeof(xx));

}

EXTERN_C BOOLEAN WINAPI AR_DriverLoad() {
	if (AR_TestComm()) {
		return TRUE;
	}
	installDriver(DriverName, DriverDir);
	return AR_TestComm();
}

EXTERN_C BOOLEAN WINAPI AR_UnDriverLoad() {
	
	return UnLoadDriver(DriverName);
}



EXTERN_C ULONG64 WINAPI AR_GetMoudle(DWORD Pid, char* moduleName) {
	ModuleInfo info = { 0 };
	info.Pid = Pid;
	info.ModuleName = (ULONG64)moduleName;

	DriverComm(CMD_GETMODULE, &info, sizeof(ModuleInfo));

	return info.Module;
}

EXTERN_C BOOLEAN WINAPI AR_ReadMemory(DWORD pid, ULONG64 BaseAddress, PVOID Buffer, ULONG size) {
	ReadWriteInfo info = { 0 };
	info.pid = pid;
	info.BaseAddress = BaseAddress;
	info.Buffer = (ULONG64)Buffer;
	info.size = size;

	return DriverComm(CMD_READ, &info, sizeof(ReadWriteInfo));
}
EXTERN_C BOOLEAN WINAPI AR_WriteMemory(DWORD pid, ULONG64 BaseAddress, PVOID Buffer, ULONG size) {
	ReadWriteInfo info = { 0 };
	info.pid = pid;
	info.BaseAddress = BaseAddress;
	info.Buffer = (ULONG64)Buffer;
	info.size = size;

	return DriverComm(CMD_WRITE, &info, sizeof(ReadWriteInfo));
}
EXTERN_C BOOLEAN WINAPI AR_QueryMemory(DWORD pid, ULONG64 BaseAddress, PMEMORY_BASIC_INFORMATION memInfo) {
	QueryMemInfo info = { 0 };
	info.pid = pid;
	info.BaseAddress = BaseAddress;

	BOOLEAN bRet = DriverComm(CMD_QUERY_MEM, &info, sizeof(QueryMemInfo));

	memcpy(memInfo, &info.memInfo, sizeof(MEMORY_BASIC_INFORMATION));

	return bRet;
}

EXTERN_C BOOLEAN WINAPI AR_EnableProtectProcess(DWORD pid) {
	ProtectInfo info = { 0 };
	info.pid = pid;
	info.state = PROTECT_ENABLE;

	return DriverComm(CMD_PROTECT_PROCESS, &info, sizeof(ProtectInfo));

}
EXTERN_C BOOLEAN WINAPI AR_DisableProtectProcess(DWORD pid) {
	ProtectInfo info = { 0 };
	info.pid = pid;
	info.state = PROTECT_DISABLE;

	return DriverComm(CMD_PROTECT_PROCESS, &info, sizeof(ProtectInfo));

}
EXTERN_C BOOLEAN WINAPI AR_RemoteCall(DWORD pid, PVOID shellcode, ULONG64 shellcodeSize) {
	RemoteCallInfo info = { 0 };
	info.pid = pid;
	info.shellcode = (ULONG64)shellcode;
	info.shellcodeSize = shellcodeSize;

	return DriverComm(CMD_REMOTE_CALL, &info, sizeof(RemoteCallInfo));

}