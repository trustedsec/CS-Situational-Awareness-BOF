


#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
BOOL SHAFile(LPCSTR lpszFile) {
    HCRYPTPROV	hProv;
    HCRYPTHASH	hHash;
    HANDLE		hFile;
    DWORD		dwBytesRead;
    BYTE		bReadFile[0x512];
    BYTE		bSHA[32]; // 32 Bytes, 256 bits

	// Open existing file, if it does not exist the call will fail and alert user.
    hFile = KERNEL32$CreateFileA(lpszFile, FILE_READ_ACCESS, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Error: Could not find file \"%s\"", lpszFile);
        return(FALSE);
    }

    if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        KERNEL32$CloseHandle(hFile);
        BeaconPrintf(CALLBACK_ERROR, "Error: Could not initilize HCRYPTPROV context");

        return(FALSE);
    }
    if (!ADVAPI32$CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        KERNEL32$CloseHandle(hFile);
        ADVAPI32$CryptReleaseContext(hProv, 0);
        BeaconPrintf(CALLBACK_ERROR, "Error: CryptCreateHash failed");
        return(FALSE);
    }
    while (KERNEL32$ReadFile(hFile, bReadFile, sizeof(bReadFile), &dwBytesRead, NULL)) {
        if (dwBytesRead == 0) {
            break; // End of file
        }
        ADVAPI32$CryptHashData(hHash, bReadFile, dwBytesRead, 0);
    }
    dwBytesRead = 32; 
    CHAR hash[256] = "";
    if (ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, bSHA, &dwBytesRead, 0)) {
        for (DWORD i = 0; i < dwBytesRead; i++){
           CHAR digits[3];
           MSVCRT$sprintf(digits, "%02X", bSHA[i]);
           MSVCRT$strcat(hash, digits);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "SHA-256 Hash for %s: %s", lpszFile, hash);
    }
    ADVAPI32$CryptReleaseContext(hProv, 0);
    ADVAPI32$CryptDestroyHash(hHash);
    KERNEL32$CloseHandle(hFile);
    return(TRUE);
}


#ifdef BOF

#include<bofdefs.h>
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
    LPCSTR server;
    datap parser;
    BeaconDataParse(&parser, Buffer, Length);
	server = (LPCSTR)BeaconDataExtract(&parser, NULL);
	if (!bofstart())
	{
		return;
	}	
	SHAFile(server);
};

#else
int main(int argc, char ** argv)
{   
	if(argc >= 2){
		LPCSTR server = (LPCSTR)argv[1];
		SHAFile(server);
	}
}

#endif