#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <tchar.h>
#include <stdio.h>

void getEnvs() {
    LPTSTR lpszVariable; 
    LPTCH lpvEnv; 
 
    // Get a pointer to the environment block. 
    lpvEnv = KERNEL32$GetEnvironmentStrings();

    internal_printf("Gathering Process Environment Variables:\n\n");

    // If the returned pointer is NULL, exit.
    if (lpvEnv == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "GetEnvironmentStrings failed.");
        return;
    }
 
    // Variable strings are separated by NULL byte, and the block is 
    // terminated by a NULL byte. 
    lpszVariable = (LPTSTR) lpvEnv;

    while (*lpszVariable)
    {   
        internal_printf("%s\n", lpszVariable);
        lpszVariable += KERNEL32$lstrlenA(lpszVariable) + 1;
    }
    KERNEL32$FreeEnvironmentStringsA(lpvEnv);
    return;
}

#ifdef BOF
VOID go() 
{
	
    if(!bofstart())
    {
        return;
    }

    getEnvs();

	printoutput(TRUE);
	bofstop();
};
#else
int main()
{
    getEnvs();
    return 1;
}
#endif
