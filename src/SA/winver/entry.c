#include <windows.h>
#include "beacon.h"

typedef NTSTATUS (NTAPI *fpRtlGetVersion)(PRTL_OSVERSIONINFOEXW lpVersionInformation);
typedef LONG (WINAPI *fpRegGetValueW)(HKEY hkey,LPCWSTR lpSubKey,LPCWSTR lpValue,DWORD dwFlags,LPDWORD pdwType,PVOID pvData,LPDWORD pcbData);
DWORD GetUBR()
{
	HANDLE hAdvapi = LoadLibraryA("advapi32.dll");
	fpRegGetValueW regval = (fpRegGetValueW)GetProcAddress(hAdvapi, "RegGetValueW");
	if(regval == NULL)
	{
		if(hAdvapi)
		{
			FreeLibrary(hAdvapi);
		}
		BeaconPrintf(CALLBACK_ERROR, "Failed to load RegGetValueW, can't return minor build number (the 0 is error value)\n");
		return 0;
	}
    DWORD ubr = 0, size = sizeof(DWORD);
    LSTATUS rc = regval(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        L"UBR", RRF_RT_REG_DWORD, NULL, &ubr, &size);
	FreeLibrary(hAdvapi);
    return rc == ERROR_SUCCESS ? ubr : 0;
}

//I am intentionally coding this differently from my normal style to address some misconceptions I see in typical AI produced bofs in regards to how LoadLibrary / GetModuleHandle and GetProcAdress are used

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	RTL_OSVERSIONINFOEXW osVerInfo = {0};
	HANDLE hntdll = GetModuleHandleA("ntdll.dll");
	fpRtlGetVersion getver = (fpRtlGetVersion)GetProcAddress(hntdll, "RtlGetVersion");
	if(getver == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "Unable to resolve RtlGetVersion, unable to retreive build version\n");
		return;
	}
	osVerInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	getver(&osVerInfo);
	BeaconPrintf(CALLBACK_OUTPUT,
"Windows Version info\n\
Build Number: %lu.%lu\n",
osVerInfo.dwBuildNumber,
GetUBR());



};

