#include <iostream>
#include "Api.h"

int main(){

	/*
	if (AR_DriverLoad()) {
		DWORD pid = 8208;
		ULONG64 addr = AR_GetMoudle(pid, _strdup("Kernel32.dll"));
		printf("baseAddr [+]: %llx\n", addr);

		MEMORY_BASIC_INFORMATION memInfo = { 0 };
		AR_QueryMemory(pid, addr, &memInfo);
		printf("AllocationBase [+]: %llx\n", memInfo.AllocationBase);
		printf("AllocationProtect [+]: %llx\n", memInfo.AllocationProtect);
		printf("BaseAddress [+]: %llx\n", memInfo.BaseAddress);
		printf("Protect [+]: %llx\n", memInfo.Protect);
		printf("RegionSize [+]: %llx\n", memInfo.RegionSize);
		printf("State [+]: %llx\n", memInfo.State);
		printf("Type [+]: %llx\n", memInfo.Type);

		

		// char buf[4] = { 'T','X' ,'S' ,'B' };
		// AR_WriteMemory(pid, 0x7FFFE1000, buf, sizeof(buf));

		// ULONG64 buffer = NULL;
		// AR_ReadMemory(pid, addr + 0x40, &buffer, sizeof(buffer));
		// printf("readBuffer [+]: %llx\n", buffer);
	}

	// ULONG64 addr = AR_GetMoudle(7784, _strdup("Kernel32.dll"));
	// ULONG64 buffer = NULL;
	// AR_ReadMemory(7784, addr, &buffer, sizeof(buffer));

	system("pause");
	AR_UnDriverLoad();
	*/
	AR_DriverLoad();
	system("pause");

	DWORD pid = 8996;
	HMODULE user32dll = LoadLibrary(L"user32.dll");
	ULONG_PTR msgBox = (ULONG_PTR)GetProcAddress(user32dll, "MessageBoxA");
	char bufcode[] = {
		0x31, 0xC9,
		0x31, 0xD2,
		0x4D, 0x31, 0xC0,
		0x4D, 0x31, 0xC9,
		0x48, 0xB8, 0x99, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00,
		0x48, 0x81, 0xEC, 0xA8, 0x00, 0x00, 0x00,
		0xFF, 0xD0,
		0x48, 0x81, 0xC4, 0xA8, 0x00, 0x00, 0x00,
		0xC3
	};
	*(PULONG64)&bufcode[12] = msgBox;


	AR_RemoteCall(pid, bufcode, sizeof(bufcode));
	system("pause");
	AR_UnDriverLoad();
}
