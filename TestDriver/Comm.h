#pragma once

#include "../LoadDriverR3/CommStruct.h"
#include <ntimage.h>


typedef NTSTATUS(NTAPI* CommCallBackProc)(PCommPackage package);

typedef NTSTATUS(*FileCallBack) (HANDLE FileHandle, PVOID info, PVOID un1, PVOID un2);
typedef NTSTATUS(*FileCallBackWin10) (PVOID info, PVOID un1, PVOID un2);

typedef struct _EX_ATTRIBUTE_INFORMATION_REGISTRATION {
	FileCallBack QueryRoutine;
	FileCallBack SetRoutine;
}EX_ATTRIBUTE_INFORMATION_REGISTRATION,*PEX_ATTRIBUTE_INFORMATION_REGISTRATION;



typedef NTSTATUS(NTAPI* pExRegisterAttributeInformationCallback)(PEX_ATTRIBUTE_INFORMATION_REGISTRATION registration);

NTSTATUS RegisterComm(CommCallBackProc commRoutine);
NTSTATUS UnRegisterComm();

