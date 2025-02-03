#include <ntifs.h>    
#include "Module.h"
#include "Comm.h"
#include "Search.h"
#include "RW.h"
#include "ProtectProcess.h"
#include "FarCall.h"

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
           DbgPrintEx(77, 0, "status [+]: %x\n", status);

        }
        break;
    }
    case CMD_WRITE: {
        PReadWriteInfo info = (PReadWriteInfo)data;
        if (info) {
            status = WriteMemory1(info->pid, info->BaseAddress, info->Buffer, info->size);
        }
        break;
    }case CMD_QUERY_MEM: {
        PQueryMemInfo info = (PQueryMemInfo)data;
        status = QueryMemory(info->pid, info->BaseAddress, &info->memInfo);

        break;
    }case CMD_PROTECT_PROCESS: {
        PProtectInfo info = (PProtectInfo)data;
        if (info->state == PROTECT_ENABLE) {
            SetProtectPid(info->pid);
            status = InitObProtect();
        }
        else if (info->state == PROTECT_DISABLE) {
            DbgBreakPoint();
            DestoryObProtect();
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_NOT_IMPLEMENTED;
        }

        break;
    }
    case CMD_REMOTE_CALL: {
        PRemoteCallInfo info = (PRemoteCallInfo)data;

        status = RemoteCall(info->pid, info->shellcode, info->shellcodeSize);

        break;
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
    DbgPrintEx(77, 0, "status[+]: %x\n", status);


    
    DriverObject->DriverUnload = UnloadDriver;
    return STATUS_SUCCESS;
}