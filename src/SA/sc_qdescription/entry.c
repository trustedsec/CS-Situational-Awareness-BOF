#include <windows.h>
#include "bofdefs.h"
#include "base.c"

DWORD query_service_description(const char* Hostname, LPCSTR cpServiceName)
{
	DWORD dwResult = ERROR_SUCCESS;
	SC_HANDLE scManager = NULL;
	SC_HANDLE scService = NULL;
	DWORD bytesneeded = 0;
	SERVICE_DESCRIPTIONA * desc = NULL;
	do
	{

		if ((scManager = ADVAPI32$OpenSCManagerA(Hostname, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | GENERIC_READ)) == NULL)
		{
			dwResult = KERNEL32$GetLastError();
            break;
		}

		if ((scService = ADVAPI32$OpenServiceA(scManager, cpServiceName,  GENERIC_READ)) == NULL)
		{
			dwResult = KERNEL32$GetLastError();
			break;
		}

		ADVAPI32$QueryServiceConfig2A(scService, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &bytesneeded);
		desc = intAlloc(bytesneeded);
		if(ADVAPI32$QueryServiceConfig2A(scService, SERVICE_CONFIG_DESCRIPTION, (LPBYTE)desc, bytesneeded, &bytesneeded) == 0)
		{
			dwResult = KERNEL32$GetLastError();
			break;
		}
		internal_printf("%s", desc->lpDescription);


	} while (0);

	if (scService)
	{
		ADVAPI32$CloseServiceHandle(scService);
	}

	if (scManager)
	{
		ADVAPI32$CloseServiceHandle(scManager);
	}
	if(desc != NULL)
	{
		intFree(desc);
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

	DWORD result = 0;
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	hostname = BeaconDataExtract(&parser, NULL);
	servicename = BeaconDataExtract(&parser, NULL);
	if(!bofstart())
	{
		return;
	}
	result = query_service_description(hostname, servicename);
	if(result != S_OK)
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to query service: %u", result);
	}
	printoutput(TRUE);
};

#else
int main()
{

	query_service_description("", "webclient");
	query_service_description("172.31.0.1", "WerSvc");
	query_service_description("asdf", "nope");
	query_service_description("", "nope");
	query_service_description("172.31.0.1", "nope");
	return 0;
}

#endif
