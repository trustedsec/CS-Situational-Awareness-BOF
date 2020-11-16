#include <windows.h>
#include <iphlpapi.h>
#include "bofdefs.h"
#include "base.c"

BOOL ALL = TRUE;
int JUNK = 1; // just to make it not get relocation error

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam){
    char WindowName[128] = {0};
    DWORD WinLen = USER32$GetWindowTextA(hwnd, WindowName, 127);

    if (WindowName[0] != 0 && WinLen){
		if(ALL)
		{
	 		internal_printf("%-40s : %s\n", WindowName, (USER32$IsWindowVisible(hwnd) ? "Visible" : "Hidden"));
		}
		else
		{
			if(USER32$IsWindowVisible(hwnd))
			{
				internal_printf("%s\n", WindowName);
			}
		}
		
    }
    return 1;
}

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	ALL = (BOOL)BeaconDataInt(&parser);
	if(!bofstart())
	{
		return;
	}
	USER32$EnumDesktopWindows(NULL,(WNDENUMPROC)EnumWindowsProc,(LPARAM)NULL);
	printoutput(TRUE);
};

#else

int main(int argc, char ** argv)
{
	ALL = atoi(argv[1]);
	USER32$EnumDesktopWindows(NULL,(WNDENUMPROC)EnumWindowsProc,(LPARAM)NULL);
	printoutput(TRUE);
	return 0;
}

#endif
