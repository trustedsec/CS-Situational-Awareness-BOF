#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "anticrash.c"

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{

	int iResult;
	#define BUFFER_SIZE 85
	WCHAR name[BUFFER_SIZE];
	WCHAR wcBuffer[BUFFER_SIZE];
	WCHAR sysTime[BUFFER_SIZE];
	WCHAR geoid[BUFFER_SIZE];
	iResult = KERNEL32$GetSystemDefaultLocaleName(name, BUFFER_SIZE);
	if(!iResult) {
		DWORD error = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "Error retrieving system locale information: %ld", error);
	}
	
	iResult = KERNEL32$GetLocaleInfoEx(name, LOCALE_SENGLANGUAGE, wcBuffer, BUFFER_SIZE);
	if(!iResult) {
		DWORD error = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "Error retrieving language: %ld", error);
	}
	
	LCID lcid = KERNEL32$LocaleNameToLCID(name, 0);
	if(!lcid) {
		DWORD error = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "Error mapping Locale Name to a Locale ID: %ld", error);
	}
	
	iResult = KERNEL32$GetDateFormatEx(name, DATE_LONGDATE, NULL, NULL, sysTime, BUFFER_SIZE, NULL);
	if(!iResult) {
		DWORD error = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "Error retrieving system date/time: %ld", error);
	}
	
	iResult = KERNEL32$GetLocaleInfoEx(name, LOCALE_SLOCALIZEDCOUNTRYNAME, geoid, BUFFER_SIZE);
	if(!iResult) {
		DWORD error = KERNEL32$GetLastError();
		BeaconPrintf(CALLBACK_ERROR, "Error retrieving geolocation id: %ld", error);
	}
	BeaconPrintf(CALLBACK_OUTPUT, "Locale: %S (%S)\nLCID: %x\nDate: %S\nCountry: %S\n", wcBuffer, name, lcid, sysTime, geoid); 	
	return;
}

#ifndef BOF
int main() {
	go(NULL, 0);
	return 0;
}
#endif

