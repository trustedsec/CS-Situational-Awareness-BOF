#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "anticrash.c"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-conversion"
const char * gServiceName = 1;
#pragma GCC diagnostic pop
char * resolveAction(DWORD a)
{
	if(a == 0){return "NONE";}
	else if(a == 1){return "RESTART";}
	else if(a == 2){return "REBOOT";}
	else if(a == 3){return "COMMAND";}
	else{return "(FAILED TO RESOLVE)";}
}

DWORD get_service_failure(SC_HANDLE scService)
{
	DWORD dwResult = ERROR_SUCCESS;
	LPSERVICE_FAILURE_ACTIONSA lpServiceConfig = NULL;
	DWORD cbBytesNeeded = 0;

	do
	{
		ADVAPI32$QueryServiceConfig2A(scService, SERVICE_CONFIG_FAILURE_ACTIONS, NULL, 0, &cbBytesNeeded);
		dwResult = KERNEL32$GetLastError();

		if (dwResult != ERROR_INSUFFICIENT_BUFFER)
		{
            break;
		}

		if ((lpServiceConfig = (LPSERVICE_FAILURE_ACTIONSA)intAlloc(cbBytesNeeded)) == NULL)
		{
            break;
		}

		if (!ADVAPI32$QueryServiceConfig2A(scService, SERVICE_CONFIG_FAILURE_ACTIONS, (LPBYTE)lpServiceConfig, cbBytesNeeded, &cbBytesNeeded))
		{
			dwResult = KERNEL32$GetLastError();
            break;
		}

		internal_printf(
"SERVICE_NAME: %s\n\
\t%-30s : %lu\n\
\t%-30s : %s\n\
\t%-30s : %s\n",
gServiceName,
"RESET_PERIOD (in seconds)", lpServiceConfig->dwResetPeriod,
"REBOOT_MESSAGE", (lpServiceConfig->lpRebootMsg) ? lpServiceConfig->lpRebootMsg : "",
"COMMAND_LINE", (lpServiceConfig->lpCommand) ? lpServiceConfig->lpCommand : ""
);
		for(DWORD x = 0; x < lpServiceConfig->cActions; x++)
		{
			internal_printf("\t%-30s : %s -- Delay = %lu milliseconds\n", "FAILURE_ACTIONS", resolveAction(lpServiceConfig->lpsaActions[x].Type), lpServiceConfig->lpsaActions[x].Delay);
		}
		dwResult = ERROR_SUCCESS;
	} while (0);

	if (lpServiceConfig)
	{
		intFree(lpServiceConfig);
	}

	return dwResult;
}

DWORD query_config(const char* Hostname, LPCSTR cpServiceName)
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
		dwResult = get_service_failure(scService);
		if(dwResult)
			break;

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
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	hostname = BeaconDataExtract(&parser, NULL);
	servicename = BeaconDataExtract(&parser, NULL);
	gServiceName = servicename;
	if(!bofstart())
	{
		return;
	}
	DWORD result = query_config(hostname, servicename);
	if(result != S_OK)
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to query service: %lu", result);
	}
	printoutput(TRUE);
};

#else

int main()
{
	gServiceName = "TestsvcName";
	query_config("", "webclient");
	query_config("172.31.0.1", "WerSvc");
	query_config("asdf", "nope");
	query_config("", "nope");
	query_config("172.31.0.1", "nope");
	return 0;
}

#endif
