#include <windows.h>
#include <stdio.h>
#include "psapi.h"
#include "bofdefs.h"
#include "base.c"

// Inspired from: https://www.codeguru.com/cpp/w-p/win32/versioning/article.php/c4539/Versioning-in-Windows.htm
int PrintSingleModule(char* szFile){
    DWORD dwLen, dwUseless;
    LPTSTR lpVI;
    char* companyName;

    dwLen = VERSION$GetFileVersionInfoSizeA((LPTSTR)szFile, &dwUseless);
    if (dwLen==0){
        internal_printf("%-50sERROR: Could not GetFileVersionInfoSizeA() on the DLL.\n", szFile);
        return 1;
    }

    lpVI = (LPTSTR) KERNEL32$GlobalAlloc(GPTR, dwLen);
    if (lpVI) {
        DWORD dwBufSize;
        VS_FIXEDFILEINFO* lpFFI;
        BOOL bRet = FALSE;
        WORD* langInfo;
        UINT cbLang;
        char szVerDescription[128];
        char szVerCompanyName[128];
        LPVOID lpDescription;
        LPVOID lpCompanyName;
        UINT cbBufSize;

        VERSION$GetFileVersionInfoA((LPTSTR)szFile, 0, dwLen, lpVI);

        //First, to get string information, we need to get
        //language information.
        VERSION$VerQueryValueA(lpVI, "\\VarFileInfo\\Translation", (LPVOID*)&langInfo, &cbLang);

        // Get Description
        MSVCRT$sprintf(szVerDescription, "\\StringFileInfo\\%04x%04x\\%s", langInfo[0], langInfo[1], "FileDescription");
        VERSION$VerQueryValueA(lpVI, szVerDescription, &lpDescription, &cbBufSize);

        // Get Company Name
        MSVCRT$sprintf(szVerCompanyName, "\\StringFileInfo\\%04x%04x\\%s", langInfo[0], langInfo[1], "CompanyName");
        VERSION$VerQueryValueA(lpVI, szVerCompanyName, &lpCompanyName, &cbBufSize);

        // Print line
        internal_printf("%-50s%-25s%-25s\n", szFile, (LPTSTR)lpCompanyName, (LPTSTR)lpDescription);

        //Cleanup
        KERNEL32$GlobalFree((HGLOBAL)lpVI);
    } else {
        internal_printf("ERROR: Could not allocate memory\n");
    }
    return 0;
}

int PrintModules(DWORD processID)
{
    HMODULE* hMods; 
    HANDLE hProcess;
    DWORD cbNeeded, cbNeeded2;
    unsigned int i;
    char szModName[MAX_PATH];

    // Print the process identifier. (debug)
    //BeaconPrintf(CALLBACK_OUTPUT, "Process ID: %u\n", processID );

    // Get a handle to the process.
    hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (NULL == hProcess)
        return 1;

    // Get size needed before requesting hMods
    if(!PSAPI$EnumProcessModulesEx(hProcess, 0, 0, &cbNeeded, LIST_MODULES_ALL)){
        internal_printf("Failed to enumerate modules\n");
        return 1;
    }

    // Allocating space for hMods
    hMods = (HMODULE*)intAlloc(cbNeeded);
    
    // Requesting hMods
    if(PSAPI$EnumProcessModulesEx(hProcess, hMods, cbNeeded, &cbNeeded2, LIST_MODULES_ALL)) {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ ) {
            // Get the full path to the module's file.
            if (PSAPI$GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                PrintSingleModule(szModName);
            }
        } 
    }

    // Free hMods allocated space
    intFree(hMods);

    // Release the handle to the process.
    KERNEL32$CloseHandle(hProcess);
    return 0;
}

// TODO: Perform recon on arbitrary PID. Could be a useful check before remote injection. 
// TODO: Add an argument to exclude Microsoft DLLs.
void go(char * args, int length) {

    if(!bofstart()) {
      return;
    }

    PrintModules(KERNEL32$GetCurrentProcessId());

    printoutput(TRUE);
    bofstop();

    return;
}
