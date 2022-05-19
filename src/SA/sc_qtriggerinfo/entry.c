#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "anticrash.c"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-conversion"
char ** ETriggerType = 1;
char ** Estartstop = 1;
const char * gServiceName = 1;
#pragma GCC diagnostic pop
#ifndef SERVICE_CONFIG_TRIGGER_INFO
#define SERVICE_CONFIG_TRIGGER_INFO 8
#endif
#ifdef __MINGW32__
typedef struct _SERVICE_TRIGGER_SPECIFIC_DATA_ITEM {
  DWORD dwDataType;
  DWORD cbData;
  PBYTE pData;
} SERVICE_TRIGGER_SPECIFIC_DATA_ITEM, *PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM;
typedef struct _SERVICE_TRIGGER {
  DWORD                               dwTriggerType;
  DWORD                               dwAction;
  GUID                                *pTriggerSubtype;
  DWORD                               cDataItems;
  PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM pDataItems;
} SERVICE_TRIGGER, *PSERVICE_TRIGGER;
typedef struct _SERVICE_TRIGGER_INFO {
  DWORD            cTriggers;
  PSERVICE_TRIGGER pTriggers;
  PBYTE            pReserved;
} SERVICE_TRIGGER_INFO, *PSERVICE_TRIGGER_INFO;
#endif

void init_enums()
{
	ETriggerType = antiStringResolve(21, "", "DEVICE_ARRIVAL", "IP_UP_DOWN", "DOMAIN_JOIN_LEAVE", "FIREWALL_PORT_EVENT", "GROUP_POLICY_UPDATE", "NETWORK_ENDPOINT", "", "", "", ""\
										 "", "", "", "", "", "", "", "", "", "", "CUSTOM");
	Estartstop = antiStringResolve(3, "", "START_SERVICE", "STOP_SERVICE");
}

void cleanup_enums()
{
	intFree(ETriggerType);
	intFree(Estartstop);
}

DWORD get_service_triggers(SC_HANDLE scService)
{
	DWORD dwResult = ERROR_SUCCESS;
	PSERVICE_TRIGGER_INFO lpServiceConfig = NULL;
	DWORD cbBytesNeeded = 0;

	do
	{
		ADVAPI32$QueryServiceConfig2A(scService, SERVICE_CONFIG_TRIGGER_INFO,  NULL, 0, &cbBytesNeeded);
		dwResult = KERNEL32$GetLastError();

		if (dwResult != ERROR_INSUFFICIENT_BUFFER)
		{
            break;
		}

		if ((lpServiceConfig = (PSERVICE_TRIGGER_INFO)intAlloc(cbBytesNeeded)) == NULL)
		{
            break;
		}

		if (!ADVAPI32$QueryServiceConfig2A(scService, SERVICE_CONFIG_TRIGGER_INFO, (LPBYTE) lpServiceConfig, cbBytesNeeded, &cbBytesNeeded))
		{
			dwResult = KERNEL32$GetLastError();
            break;
		}
		if(lpServiceConfig->cTriggers == 0)
		{
			internal_printf("The service %s has not registered for any start or stop triggers.\n", gServiceName);
			dwResult = ERROR_SUCCESS;
			break;
		}
		internal_printf("SERVICE_NAME: %s\n\n",gServiceName);

		for(DWORD x = 0; x < lpServiceConfig->cTriggers; x++)
		{
			RPC_CSTR guid = NULL;
			RPCRT4$UuidToStringA(lpServiceConfig->pTriggers[x].pTriggerSubtype, &guid);
			internal_printf("\t%s\n", (lpServiceConfig->pTriggers[x].dwAction > 0 && lpServiceConfig->pTriggers[x].dwAction < 3) ? Estartstop[lpServiceConfig->pTriggers[x].dwAction] : "(FAILED TO RESOLVE)");
			internal_printf("\t  %-20s : %s\n", 
			(lpServiceConfig->pTriggers[x].dwTriggerType < 21 && lpServiceConfig->pTriggers[x].dwTriggerType > 0) ? ETriggerType[lpServiceConfig->pTriggers[x].dwTriggerType] : "(FAILED TO RESOLVE)",
			(guid) ? (char *)guid : "(FAILED)");
			if(guid) {RPCRT4$RpcStringFreeA(&guid);} //set to null on loop
			if( (lpServiceConfig->pTriggers[x].dwTriggerType == 20 || lpServiceConfig->pTriggers[x].dwTriggerType == 1 || lpServiceConfig->pTriggers[x].dwTriggerType == 4\
				|| lpServiceConfig->pTriggers[x].dwTriggerType == 6) && lpServiceConfig->pTriggers[x].cDataItems)
				{
					internal_printf("Has trigger specific data items but currently this is unsupported\n");
				}
			internal_printf("\n");
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
		dwResult = get_service_triggers(scService);
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
	init_enums();
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
		BeaconPrintf(CALLBACK_ERROR, "Failed to query service: %u", result);
	}
	printoutput(TRUE);
	cleanup_enums();
};
#else

int main()
{
	init_enums();
	gServiceName = "TestsvcName";
	query_config("", "webclient");
	query_config("172.31.0.1", "WerSvc");
	query_config("asdf", "nope");
	query_config("", "nope");
	query_config("172.31.0.1", "nope");
	cleanup_enums();
}

#endif
