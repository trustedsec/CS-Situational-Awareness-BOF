#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

BOOL SHA1File(LPCSTR lpszFile) {
    HCRYPTPROV  hProv;
    HCRYPTHASH  hHash;
    HANDLE      hFile;
    DWORD       dwBytesRead;
    BYTE        bReadFile[0x512];
    BYTE        bSHA1[20]; // 20 bytes = 160-bit SHA1

    // Open file
    hFile = KERNEL32$CreateFileA(lpszFile, FILE_READ_ACCESS, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Error: Could not find file \"%s\"", lpszFile);
        return FALSE;
    }

    // Acquire crypto context
    if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        KERNEL32$CloseHandle(hFile);
        BeaconPrintf(CALLBACK_ERROR, "Error: Could not initialize HCRYPTPROV context");
        return FALSE;
    }

    // Create SHA1 hash
    if (!ADVAPI32$CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
        ADVAPI32$CryptReleaseContext(hProv, 0);
        KERNEL32$CloseHandle(hFile);
        BeaconPrintf(CALLBACK_ERROR, "Error: CryptCreateHash (SHA1) failed");
        return FALSE;
    }

    // Read file and hash it
    while (KERNEL32$ReadFile(hFile, bReadFile, sizeof(bReadFile), &dwBytesRead, NULL)) {
        if (dwBytesRead == 0) {
            break; // EOF
        }
        ADVAPI32$CryptHashData(hHash, bReadFile, dwBytesRead, 0);
    }

    // Get SHA1 digest
    dwBytesRead = sizeof(bSHA1);
    CHAR hash[64] = "";

    if (ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, bSHA1, &dwBytesRead, 0)) {
        for (DWORD i = 0; i < dwBytesRead; i++) {
            CHAR digits[3];
            MSVCRT$sprintf(digits, "%02X", bSHA1[i]);
            MSVCRT$strcat(hash, digits);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "SHA1 Hash for %s: %s", lpszFile, hash);
    }

    // Cleanup
    ADVAPI32$CryptDestroyHash(hHash);
    ADVAPI32$CryptReleaseContext(hProv, 0);
    KERNEL32$CloseHandle(hFile);

    return TRUE;
}

#ifdef BOF

VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    LPCSTR file;
    datap parser;

    BeaconDataParse(&parser, Buffer, Length);
    file = (LPCSTR) BeaconDataExtract(&parser, NULL);

    if (!bofstart()) {
        return;
    }

    SHA1File(file);
}

#else

int main(int argc, char **argv)
{
    if (argc >= 2) {
        LPCSTR file = (LPCSTR)argv[1];
        SHA1File(file);
    }
}

#endif
