#include <iostream>
#include "Api.h"

int main(){

	if (AR_DriverLoad()) {
		ULONG64 addr = AR_GetMoudle(9004,_strdup("Kernel32.dll"));
		printf("baseAddr [+]: %llx\n", addr);
		ULONG64 buffer = NULL;
		AR_ReadMemory(9004, addr, &buffer, sizeof(buffer));
		printf("readBuffer [+]: %llx\n", buffer);
	
	}

	// ULONG64 addr = AR_GetMoudle(7784, _strdup("Kernel32.dll"));
	// ULONG64 buffer = NULL;
	// AR_ReadMemory(7784, addr, &buffer, sizeof(buffer));

	system("pause");
	 AR_UnDriverLoad();
}
