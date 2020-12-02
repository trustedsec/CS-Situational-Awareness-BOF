#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "anticrash.c"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-conversion"
char ** EServiceStatus = 1;
const char * gServiceName = 1;
#pragma GCC diagnostic pop

void init_enums()
{
	EServiceStatus = antiStringResolve(7, "SPACER", "STOPPED", "START_PENDING", "STOP_PENDING", "RUNNING", "CONTINUE_PENDING", "PAUSE_PENDING");
}

char * resolveType(DWORD T)
{
	if(T == 0x1){
		return "KERNEL_DRIVER";
	 } else if (T == 0x2) {
		return "FILE_DRIVER";
	 } else if (T == 0x10 || T == 0x110) {
		return (T == 0x10) ? "WIN32_OWN" : "WIN32_OWN Interactive";
	 } else if (T == 0x20 || T == 0x120) {
		 return (T == 0x20) ? "WIN32_SHARED" : "WIN32_SHARED Interactive";
	 } else if (T == 0x50 ||T == 0xD0) {
		 return (T == 0x50) ? "USER_OWN" : "USER_OWN Instance";
	 } else if (T == 0x60 || T == 0xE0) {
		 return (T == 0x60) ? "USER_SHARED" : "USER_SHARED Instance";
	 } else{
		 return "UNKNOWN";
	 }
}

void cleanup_enums()
{
	intFree(EServiceStatus);
}

DWORD get_service_status(SC_HANDLE scService)
{

	DWORD dwResult = ERROR_SUCCESS;
	SERVICE_STATUS_PROCESS serviceStatus;
	DWORD junk = 0;
	do
	{
		if (!ADVAPI32$QueryServiceStatusEx(scService, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatus, sizeof(SERVICE_STATUS_PROCESS), &junk))
		{
			dwResult = KERNEL32$GetLastError();
			break;
		}
			internal_printf("\
SERVICE_NAME: %s\n\
\t%-20s : %d %s\n\
\t%-20s : %d %s\n\
\t%-20s : %d\n\
\t%-20s : %d\n\
\t%-20s : %d\n\
\t%-20s : %d\n\
\t%-20s : %d\n\
\t%-20s : %d\n",
			gServiceName,
			"TYPE", serviceStatus.dwServiceType, resolveType(serviceStatus.dwServiceType),
			"STATE", serviceStatus.dwCurrentState, EServiceStatus[serviceStatus.dwCurrentState],
			"WIN32_EXIT_CODE", serviceStatus.dwWin32ExitCode,
			"SERVICE_EXIT_CODE", serviceStatus.dwServiceSpecificExitCode,
			"CHECKPOINT", serviceStatus.dwCheckPoint,
			"WAIT_HINT", serviceStatus.dwWaitHint,
			"PID", serviceStatus.dwProcessId,
			"Flags", serviceStatus.dwServiceFlags
			);
		
	} while (0);

	return dwResult;
}

DWORD enumerate_services(const char* Hostname)
{
	DWORD dwResult = ERROR_SUCCESS;
	SC_HANDLE scManager = NULL;
	ENUM_SERVICE_STATUS_PROCESSA* pSsInfo = NULL; // set by EnumServicesStatusEX which scanbuild doesn't catch
	DWORD dwBytesNeeded = 0;
	DWORD dwServicesReturned = 0;
	DWORD dwResumeHandle = 0;
	DWORD dwServiceIndex = 0;
	BOOL bResult = FALSE;

	do
	{
		if ((scManager = ADVAPI32$OpenSCManagerA(Hostname, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | GENERIC_READ)) == NULL)
		{
			dwResult = KERNEL32$GetLastError();
            break;
		}

		bResult = ADVAPI32$EnumServicesStatusExA(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0,
			&dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL);

		if (!bResult && dwBytesNeeded)
		{
			pSsInfo = (ENUM_SERVICE_STATUS_PROCESSA*)intAlloc(dwBytesNeeded);
			if (!pSsInfo)
			{
                break;
			}

			bResult = ADVAPI32$EnumServicesStatusExA(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)pSsInfo, dwBytesNeeded,
				&dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL);
			if (!bResult)
			{
				dwResult = KERNEL32$GetLastError();
				break;
			}
		}
		else
		{
			//initial query for size failed
			dwResult = KERNEL32$GetLastError();
			break;
		}


		for (dwServiceIndex = 0; dwServiceIndex < dwServicesReturned; ++dwServiceIndex)
		{
			internal_printf("\
SERVICE_NAME: %s\n\
DISPLAY_NAME: %s\n\
\t%-20s : %d %s\n\
\t%-20s : %d %s\n\
\t%-20s : %d\n\
\t%-20s : %d\n\
\t%-20s : %d\n\
\t%-20s : %d\n\
\t%-20s : %d\n\
\t%-20s : %d\n\n",
			pSsInfo[dwServiceIndex].lpServiceName,
			pSsInfo[dwServiceIndex].lpDisplayName,
			"TYPE", pSsInfo[dwServiceIndex].ServiceStatusProcess.dwServiceType, resolveType(pSsInfo[dwServiceIndex].ServiceStatusProcess.dwServiceType),
			"STATE", pSsInfo[dwServiceIndex].ServiceStatusProcess.dwCurrentState, EServiceStatus[pSsInfo[dwServiceIndex].ServiceStatusProcess.dwCurrentState],
			"WIN32_EXIT_CODE", pSsInfo[dwServiceIndex].ServiceStatusProcess.dwWin32ExitCode,
			"SERVICE_EXIT_CODE", pSsInfo[dwServiceIndex].ServiceStatusProcess.dwServiceSpecificExitCode,
			"CHECKPOINT", pSsInfo[dwServiceIndex].ServiceStatusProcess.dwCheckPoint,
			"WAIT_HINT", pSsInfo[dwServiceIndex].ServiceStatusProcess.dwWaitHint,
			"PID", pSsInfo[dwServiceIndex].ServiceStatusProcess.dwProcessId,
			"FLAGS", pSsInfo[dwServiceIndex].ServiceStatusProcess.dwServiceFlags
			);
				
		}

	} while (0);

	if (pSsInfo)
	{
		intFree(pSsInfo);
	}

	if (scManager)
	{
		ADVAPI32$CloseServiceHandle(scManager);
	}

	return dwResult;
}

DWORD query_service(const char* Hostname, LPCSTR cpServiceName)
{
	DWORD dwResult = ERROR_SUCCESS;
	SC_HANDLE scManager = NULL;
	SC_HANDLE scService = NULL;

	do
	{

		if ((scManager = ADVAPI32$OpenSCManagerA(Hostname, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | GENERIC_READ)) == NULL)
		{
			dwResult = KERNEL32$GetLastError();
            break;
		}

		if ((scService = ADVAPI32$OpenServiceA(scManager, cpServiceName, GENERIC_READ)) == NULL)
		{
			dwResult = KERNEL32$GetLastError();
			break;
		}
		dwResult = get_service_status(scService);

	} while (0);

	if (scService)
	{
		ADVAPI32$CloseServiceHandle(scService);
	}

	if (scManager)
	{
		ADVAPI32$CloseServiceHandle(scManager);
	}


	return dwResult;
}

#ifdef BOF

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	const char * hostname = NULL;
	const char * servicename = NULL;
	int slen = 0;
	DWORD result = 0;
	datap parser;
	init_enums();
	BeaconDataParse(&parser, Buffer, Length);
	hostname = BeaconDataExtract(&parser, NULL);
	servicename = BeaconDataExtract(&parser, &slen);
	gServiceName = servicename;
	if(!bofstart())
	{
		return;
	}
	if (slen == 1)
	{
		result = enumerate_services(hostname);
	}
	else
	{
		result = query_service(hostname, servicename);
	}
	if(result != S_OK)
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to query service: %u", result);
	}
	printoutput(TRUE);
	cleanup_enums();
};

#else

int main()
{
	init_enums();
	gServiceName = "testsvcName";
	enumerate_services("");
	query_service("", "webclient");
	query_service("", "nope");
	enumerate_services("172.31.0.1");
	query_service("172.31.0.1", "fax");
	enumerate_services("asdf");
	query_service("172.31.0.1", "nope");
	query_service("asdf", "nope");
	cleanup_enums();
}
#endif
