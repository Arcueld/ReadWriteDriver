#include <iostream>
#include <Windows.h>

int main(int args,char* argv[]){

    FILE *file = NULL;
    fopen_s(&file, argv[1], "rb");

    fseek(file, 0, SEEK_END);
    ULONG len = ftell(file);
    rewind(file);

    unsigned char* fileData = (unsigned char*)malloc(len);
    memset(fileData, 0, len);

    fread(fileData, len, 1, file);
    fclose(file);

    FILE* outFile = NULL;

    fopen_s(&outFile, argv[2], "wb");


    char buf[100] = {0};
    sprintf_s(buf, "unsigned char %s[%d] = {",argv[3], len);
    fputs(buf,outFile);

    // unsigned char key[] = { 0x7e, 0x26, 0x54, 0x3e }; 

    unsigned char key[] = { 0x2e, 0x76, 0x5b, 0x2f };
    size_t keyLen = sizeof(key) / sizeof(key[0]);   
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) {
            fputs("\n",outFile);
        }
        fileData[i] ^= key[i % keyLen];
        sprintf_s(buf,10, "0x%02x, ", fileData[i]);
        fputs(buf, outFile);
    }


    fputs("\n};", outFile);
    
    
    return 0;
}
