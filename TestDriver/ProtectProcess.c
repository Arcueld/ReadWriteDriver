#include "ProtectProcess.h"
#include "Search.h"


HANDLE regHandle = NULL;
HANDLE gPid = NULL;


// typedef struct _OB_CALLBACK_REGISTRATION {
//     _In_ USHORT                     Version;
//     _In_ USHORT                     OperationRegistrationCount;
//     _In_ UNICODE_STRING             Altitude;
//     _In_ PVOID                      RegistrationContext;
//     _In_ OB_OPERATION_REGISTRATION* OperationRegistration;
// } OB_CALLBACK_REGISTRATION, * POB_CALLBACK_REGISTRATION;
// 
// typedef struct _OB_OPERATION_REGISTRATION {
//     _In_ POBJECT_TYPE* ObjectType;
//     _In_ OB_OPERATION                Operations;
//     _In_ POB_PRE_OPERATION_CALLBACK  PreOperation;
//     _In_ POB_POST_OPERATION_CALLBACK PostOperation;
// } OB_OPERATION_REGISTRATION, * POB_OPERATION_REGISTRATION;
void SetProtectPid(HANDLE pid) {
    gPid = pid;
}

OB_PREOP_CALLBACK_STATUS preProtectRoutine (
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    ) {

    // DbgPrintEx(77, 0, "11111111111111\n");
    PEPROCESS process = OperationInformation->Object;
    if (!process) return OB_PREOP_SUCCESS;
    HANDLE currentPid = PsGetCurrentProcessId();
    HANDLE targetPid = PsGetProcessId(process);

    if (currentPid == gPid) return OB_PREOP_SUCCESS;
    if (targetPid != gPid) return OB_PREOP_SUCCESS;

    // Disable all
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
        OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess = 0;
    }
    else{
        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
        OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess = 0;
    }
        
    return OB_PREOP_SUCCESS;
}


PDRIVER_OBJECT GetDriverObjectByName(PWCH name) {
    UNICODE_STRING uDriverName = { 0 };
    RtlInitUnicodeString(&uDriverName, name);
    PDRIVER_OBJECT driver = NULL;
    NTSTATUS status = ObReferenceObjectByName(&uDriverName, FILE_ALL_ACCESS, NULL, NULL, *IoDriverObjectType, KernelMode, NULL, &driver);
    if (status){
        ObDereferenceObject(driver);
    }
    return driver;
}

void DestoryObProtect() {
    if (regHandle != NULL) {
        ObUnRegisterCallbacks(regHandle);
        regHandle = NULL;
    }
}
NTSTATUS patchAndRegister(POB_CALLBACK_REGISTRATION pobCallbackRegistration) {
    RTL_OSVERSIONINFOW version = { 0 };
    RtlGetVersion(&version);
    PUCHAR findFunc = NULL;

    if (version.dwBuildNumber == 7600 && version.dwBuildNumber == 7601) {
    //win7 patch
        PUCHAR func = (PUCHAR)ObRegisterCallbacks;
        for (int i = 0; i < 0x500; i++) {
            if (func[i] == 0x74 && func[i + 2] == 0xe8 && func[i + 7] == 0x3b && func[i + 8] == 0xc3) {
                LARGE_INTEGER large;
                large.QuadPart = func + i + 7;
                large.LowPart += *(PULONG)(func + i + 3);
                findFunc = large.QuadPart;
                break;
            }
        }
    }
    else{
    // win10 patch
        PUCHAR func = (PUCHAR)ObRegisterCallbacks;
        for (int i = 0; i < 0x500; i++) {
            if (func[i] == 0xBA && func[i + 5] == 0xE8 && func[i + 10] == 0x85 && func[i + 11] == 0xc0) {
                LARGE_INTEGER large;
                large.QuadPart = func + i + 10;
                large.LowPart += *(PULONG)(func + i + 6);
                findFunc = large.QuadPart;
                break;
            }
        }
    }
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (findFunc) {
        PHYSICAL_ADDRESS phy = MmGetPhysicalAddress(findFunc);
        PVOID mem = MmMapIoSpace(phy, 10, MmNonCached);
        if (mem) {
            UCHAR bufCode[10] = { 0 };
            UCHAR patch[] = { 0xb0,0x01,0xc3 };
            memcpy(bufCode, mem, 10);
            memcpy(mem, patch, sizeof(patch));
            status = ObRegisterCallbacks(pobCallbackRegistration, &regHandle);
            memcpy(mem, bufCode, 10);
        }
    }
    return status;
}

NTSTATUS InitObProtect() {
    OB_OPERATION_REGISTRATION obOpreationRegistration = { 0 };
    OB_CALLBACK_REGISTRATION obCallbackRegistration = { 0 };
    PDRIVER_OBJECT pDriver =  GetDriverObjectByName(L"\\Driver\\WMIxWDM");
    if (!pDriver) {
        return STATUS_UNSUCCESSFUL;
    }

    ULONG64 jmpRcxCode = searchCode("ntoskrnl.exe", ".text", "FFE1", 0);

    obOpreationRegistration.ObjectType = *PsProcessType;
    obOpreationRegistration.Operations = OB_OPERATION_HANDLE_CREATE| OB_OPERATION_HANDLE_DUPLICATE;
    obOpreationRegistration.PreOperation = jmpRcxCode;

    UNICODE_STRING altitude = { 0 };
    RtlInitUnicodeString(&altitude, "114514");
    obCallbackRegistration.Altitude = altitude;
    obCallbackRegistration.OperationRegistration = &obOpreationRegistration;
    obCallbackRegistration.OperationRegistrationCount = 1;
    obCallbackRegistration.Version = ObGetFilterVersion();
    obCallbackRegistration.RegistrationContext = preProtectRoutine;

    // PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
    // ldr->Flags |= 0x20;

    NTSTATUS status = patchAndRegister(&obCallbackRegistration);
    DbgPrintEx(77, 0, "%x\n", status);

    return status;
}