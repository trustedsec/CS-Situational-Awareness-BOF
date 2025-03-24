#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <ntsecapi.h>

#define SP(x) (x) ? x : L"NULL"

void PrintTimeUTC(const char * prefix, LARGE_INTEGER logonTime)
{
    FILETIME ftUtc;
    SYSTEMTIME stUtc;
	if(logonTime.LowPart == 0 && logonTime.HighPart == 0 ||
	logonTime.LowPart == UINT_MAX && logonTime.HighPart == INT_MAX)
	{
		internal_printf("%s: Unset\n", prefix);
		return;
	}
	//internal_printf("raw low / high : %lu | %lu", logonTime.LowPart, logonTime.HighPart);
    // LARGE_INTEGER to FILETIME
    ftUtc.dwLowDateTime = logonTime.LowPart;
    ftUtc.dwHighDateTime = logonTime.HighPart;

    // Convert FILETIME to SYSTEMTIME (UTC)
    if (!KERNEL32$FileTimeToSystemTime(&ftUtc, &stUtc)) {
        internal_printf("FileTimeToSystemTime failed. Error: %lu\n", KERNEL32$GetLastError());
        return;
    }

    // Print the human-readable date/time
    internal_printf("%s: %04d-%02d-%02d %02d:%02d:%02d\n",prefix,
           stUtc.wYear, stUtc.wMonth, stUtc.wDay,
           stUtc.wHour, stUtc.wMinute, stUtc.wSecond);
}

const char* LogonTypeToString(SECURITY_LOGON_TYPE type)
{
    switch (type) {
        case UndefinedLogonType:       return "UndefinedLogonType";
        case Interactive:              return "Interactive";
        case Network:                  return "Network";
        case Batch:                    return "Batch";
        case Service:                  return "Service";
        case Proxy:                    return "Proxy";
        case Unlock:                   return "Unlock";
        case NetworkCleartext:         return "NetworkCleartext";
        case NewCredentials:           return "NewCredentials";
#if _WIN32_WINNT >= 0x0501
        case RemoteInteractive:        return "RemoteInteractive";
        case CachedInteractive:        return "CachedInteractive";
#endif
#if _WIN32_WINNT >= 0x0502
        case CachedRemoteInteractive:  return "CachedRemoteInteractive";
        case CachedUnlock:             return "CachedUnlock";
#endif
        default:                       return "Unknown";
    }
}


void get_logon_data()
{
	HANDLE token;
    DWORD len;
	PSECURITY_LOGON_SESSION_DATA pLogonSessionData = NULL;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &token)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed. Error: %lu\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    TOKEN_STATISTICS stats;
    if (!ADVAPI32$GetTokenInformation(token, TokenStatistics, &stats, sizeof(stats), &len)) {
        BeaconPrintf(CALLBACK_ERROR, "GetTokenInformation failed. Error: %lu\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    NTSTATUS status = SECUR32$LsaGetLogonSessionData(&(stats.AuthenticationId), &pLogonSessionData);

    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "LsaGetLogonSessionData failed. NTSTATUS: 0x%lx\n", status);
        goto cleanup;
    }

    internal_printf("UserName: %ls\\%ls\n",
            (pLogonSessionData->LogonDomain.Buffer) ? pLogonSessionData->LogonDomain.Buffer : L"NULL",
            SP(pLogonSessionData->UserName.Buffer));

    internal_printf("Authentication Package: %ls\n",
            SP(pLogonSessionData->AuthenticationPackage.Buffer));
    internal_printf("Logon Type: %s\n", LogonTypeToString(pLogonSessionData->LogonType));
	internal_printf("Session id: %lu\n\
Logon Server: %ls\n\
DnsDomainName: %ls\n\
UPN: %ls \n\
Profile Path: %ls \n\
HomeDirectory %ls \n\
", pLogonSessionData->Session,
SP(pLogonSessionData->LogonServer.Buffer),
SP(pLogonSessionData->DnsDomainName.Buffer),
SP(pLogonSessionData->Upn.Buffer),
SP(pLogonSessionData->ProfilePath.Buffer),
SP(pLogonSessionData->HomeDirectory.Buffer));
PrintTimeUTC("Logon Time", pLogonSessionData->LogonTime);
PrintTimeUTC("Password last changed", pLogonSessionData->PasswordLastSet);
PrintTimeUTC("Password can change", pLogonSessionData->PasswordCanChange);
PrintTimeUTC("Password must change", pLogonSessionData->PasswordMustChange);


	cleanup:
	if(pLogonSessionData)
    	SECUR32$LsaFreeReturnBuffer(pLogonSessionData);
	if(token)
	{
		KERNEL32$CloseHandle(token);
	}
}

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	if(!bofstart())
	{
		return;
	}
	get_logon_data();
	printoutput(TRUE);
};

#else

int main()
{
//code for standalone exe for scanbuild / leak checks
}

#endif
