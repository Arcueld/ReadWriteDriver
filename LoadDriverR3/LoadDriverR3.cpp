#include <iostream>
#include "Api.h"

int main(){

	if (AR_DriverLoad()) {
		ULONG64 addr = AR_GetMoudle(2472, _strdup("Kernel32.dll"));
		printf("baseAddr [+]: %llx\n", addr);

		char testBuf[] = {'T', 'E', 'S', 'T'};
		ULONG size;
		AR_WriteMemory(2472, addr + 0x40, testBuf, sizeof(testBuf));

		ULONG64 buffer = NULL;
		AR_ReadMemory(2472, addr+0x40, &buffer, sizeof(buffer));
		printf("readBuffer [+]: %llx\n", buffer);
	}

	// ULONG64 addr = AR_GetMoudle(7784, _strdup("Kernel32.dll"));
	// ULONG64 buffer = NULL;
	// AR_ReadMemory(7784, addr, &buffer, sizeof(buffer));

	system("pause");
	 AR_UnDriverLoad();
}
