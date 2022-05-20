#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "anticrash.c"

DECLSPEC_IMPORT int WINAPI KERNEL32$GetLocaleInfoEx(LPCWSTR lpLocaleName, LCTYPE LCType, LPWSTR lpLCData, int cchData);
WINBASEAPI int WINAPI KERNEL32$GetSystemDefaultLocaleName(LPCWSTR lpLocaleName, int cchLocaleName);
DECLSPEC_IMPORT LCID WINAPI KERNEL32$LocaleNameToLCID(LPCWSTR lpName, DWORD dwFlags);
DECLSPEC_IMPORT int WINAPI KERNEL32$GetDateFormatEx(LPCWSTR lpLocaleName, DWORD dwFlags, const SYSTEMTIME *lpData, LPCWSTR lpFormat, LPWSTR lpDateStr, int cchDate, LPCWSTR lpCalendar);
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{

	int iResult;
	int BUFFER_SIZE = 512;
	WCHAR name[BUFFER_SIZE];
	WCHAR wcBuffer[BUFFER_SIZE];
	WCHAR sysTime[BUFFER_SIZE];
	WCHAR geoid[80];
	iResult = KERNEL32$GetSystemDefaultLocaleName(name, BUFFER_SIZE);
	if(iResult > 0) {
		iResult = KERNEL32$GetLocaleInfoEx(name, LOCALE_SENGLANGUAGE, wcBuffer, BUFFER_SIZE);
		LCID lcid = KERNEL32$LocaleNameToLCID(name, 0);
		iResult = KERNEL32$GetDateFormatEx(name, DATE_LONGDATE, NULL, NULL, sysTime, BUFFER_SIZE, NULL);
		iResult = KERNEL32$GetLocaleInfoEx(name, LOCALE_SLOCALIZEDCOUNTRYNAME, geoid, BUFFER_SIZE);
		
		
		BeaconPrintf(CALLBACK_OUTPUT, "Locale: %S (%S)\nLCID: %x\nDate: %S\nCountry: %S\n", wcBuffer, name, lcid, sysTime, geoid); 	
	} else {
		BeaconPrintf(CALLBACK_ERROR, "Error retrieving system locale information");
	}

	return;
};
