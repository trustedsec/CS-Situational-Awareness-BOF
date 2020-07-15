#include <windows.h>
#include <iphlpapi.h>
#include "bofdefs.h"
#include "base.c"

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam){
    char WindowName[80], ClassName[80];
    USER32$GetWindowTextA(hwnd, WindowName, 80);
    USER32$GetClassNameA(hwnd, ClassName, 80);
    if (WindowName[0] != 0 && USER32$IsWindowVisible(hwnd)){
		internal_printf("Name : %s\n", WindowName);
    }

    return 1;
}


VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	if(!bofstart())
	{
		return;
	}
	USER32$EnumDesktopWindows(NULL,(WNDENUMPROC)EnumWindowsProc,(LPARAM)NULL);
	printoutput(TRUE);
	bofstop();
};
