#pragma once
#include <Windows.h>
#include <iostream>

char* generateRandomString(size_t length);
BOOLEAN installDriver(LPCWSTR driverName, LPCWSTR driverPath);
LPCWSTR getRandomSysDir();
LPCWSTR getRandomSysServiceName();
BOOLEAN UnLoadDriver(LPCWSTR driverName);