#include <ntifs.h>    
#include "Module.h"
#include "Comm.h"
#include "Search.h"
#include "RW.h"

NTSTATUS NTAPI testCommCallBackProc(PCommPackage package) {
    PVOID data = package->Data;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DbgPrintEx(77,0,"%x\t%x\n", package->Cmd, package->Id);

    switch (package->Cmd){
    case CMD_TEST: {
        status = STATUS_SUCCESS;
        break;
    }
    case CMD_GETMODULE: {
        PModuleInfo info = (PModuleInfo)data;
        if (info) {
            ULONG64 imageSize = 0;
            info->Module = GetModuleR3(info->Pid,info->ModuleName,&imageSize);
            info->ModuleSize = imageSize;
            status = STATUS_SUCCESS;
        }
        break; 
    }
    case CMD_READ: {
        DbgPrintEx(77,0,"StartRead\n");
        PReadWriteInfo info = (PReadWriteInfo)data;
        if (info) {
           status = ReadMemory3(info->pid, info->BaseAddress, info->Buffer, info->size);
        }
        DbgPrintEx(77, 0, "status [+]: %x\n", status);

    }
    case CMD_WRITE: {
        DbgPrintEx(77, 0, "StartWrite\n");
        PReadWriteInfo info = (PReadWriteInfo)data;
        if (info) {
            status = WriteMemory1(info->pid, info->BaseAddress, info->Buffer, info->size);
        }

    }
    default:
        status = STATUS_NOT_IMPLEMENTED;
        break;
    }



    return status;
};


NTSTATUS UnloadDriver(PDRIVER_OBJECT DriverObject)
{
    UnRegisterComm();
}



NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = RegisterComm(testCommCallBackProc);
	DbgPrint("%x\n", status);
    
    
    DriverObject->DriverUnload = UnloadDriver;
    return STATUS_SUCCESS;
}