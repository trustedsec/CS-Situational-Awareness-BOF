#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "anticrash.c"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-conversion"
const char ** EServiceStatus = 1;
const char ** ETriggerType = 1;
const char ** Estartstop = 1;
const char ** EServiceStartup = 1;
const char ** EServiceError = 1;
SC_HANDLE gscManager = 1;
char * junk = 1;
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
	gscManager = NULL;
	//these were all moved to const compares because of BOF's relocation error, and me not being able to use my usual trick of just add a few more globals
	//Seems there is an upper limit of data items before the object files are made in such a way that the current BOF loader can't handle mingw's output in terms of globals
	//These are all actually const but I don't want to go update all my code at the moment
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	EServiceStatus = antiStringResolve(7, "SPACER", "STOPPED", "START_PENDING", "STOP_PENDING", "RUNNING", "CONTINUE_PENDING", "PAUSE_PENDING");
	EServiceStartup = antiStringResolve(5, "BOOT_DRIVER", "SYSTEM_START_DRIVER", "AUTO_START", "DEMAND_START", "DISABLED");
	ETriggerType = antiStringResolve(21, "", "DEVICE_ARRIVAL", "IP_UP_DOWN", "DOMAIN_JOIN_LEAVE", "FIREWALL_PORT_EVENT", "GROUP_POLICY_UPDATE", "NETWORK_ENDPOINT", "", "", "", ""\
										 "", "", "", "", "", "", "", "", "", "", "CUSTOM");
	Estartstop = antiStringResolve(3, "", "START_SERVICE", "STOP_SERVICE");

	EServiceError = antiStringResolve(4, "IGNORE", "NORMAL", "SEVERE", "CRITICAL");
	#pragma GCC diagnostic pop
}
char * make_long_str(LPSTR serviceinfo)
{
	DWORD i = 0;
	if(!serviceinfo || serviceinfo[0] == 0) //no depends
	{
		return "";
	} else if (serviceinfo[0] == SC_GROUP_IDENTIFIERA) // Names a service group
	{
		return serviceinfo;
	} else // Array is here, lets make it printable
	{ 
		while(! (serviceinfo[i] == 0 && serviceinfo[i+1] == 0)) // while we having hit the double null terminator
		{
			if(serviceinfo[i] == 0) {
				serviceinfo[i] = ' ';} // replace any null up to double null with a space
			i++;
		}
		return serviceinfo; // now its been modified
	}
	
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

char * resolveAction(DWORD a)
{
	if(a == 0){return "NONE";}
	else if(a == 1){return "RESTART";}
	else if(a == 2){return "REBOOT";}
	else if(a == 3){return "COMMAND";}
	else{return "(FAILED TO RESOLVE)";}
}

void cleanup_enums()
{
	intFree(EServiceStatus);
	intFree(ETriggerType);
	intFree(Estartstop);
	intFree(EServiceStartup);
	intFree(EServiceError);
	if(gscManager)
	{ADVAPI32$CloseServiceHandle(gscManager); gscManager = NULL;}
}
DWORD get_service_config(SC_HANDLE scService)
{
	DWORD dwResult = ERROR_SUCCESS;
	LPQUERY_SERVICE_CONFIGA lpServiceConfig = NULL;
	DWORD cbBytesNeeded = 0;

	do
	{
		ADVAPI32$QueryServiceConfigA(scService, NULL, 0, &cbBytesNeeded);
		dwResult = KERNEL32$GetLastError();

		if (dwResult != ERROR_INSUFFICIENT_BUFFER)
		{
            break;
		}

		if ((lpServiceConfig = (LPQUERY_SERVICE_CONFIGA)intAlloc(cbBytesNeeded)) == NULL)
		{
            break;
		}

		if (!ADVAPI32$QueryServiceConfigA(scService, lpServiceConfig, cbBytesNeeded, &cbBytesNeeded))
		{
			dwResult = KERNEL32$GetLastError();
            break;
		}

		internal_printf("\
\t%-30s : %lx %s\n\
\t%-30s : %lx %s\n\
\t%-30s : %lx %s\n\
\t%-30s : %s\n\
\t%-30s : %s\n\
\t%-30s : %ld\n\
\t%-30s : %s\n\
\t%-30s : %s%s\n\
\t%-30s : %s\n",
"TYPE", lpServiceConfig->dwServiceType, resolveType(lpServiceConfig->dwServiceType),
"START_TYPE", lpServiceConfig->dwStartType, EServiceStartup[lpServiceConfig->dwStartType],
"ERROR_CONTROL", lpServiceConfig->dwErrorControl, EServiceError[lpServiceConfig->dwErrorControl],
"BINARY_PATH_NAME", lpServiceConfig->lpBinaryPathName,
"LOAD_ORDER_GROUP", (lpServiceConfig->lpLoadOrderGroup) ? lpServiceConfig->lpLoadOrderGroup : "",
"TAG", lpServiceConfig->dwTagId,
"DISPLAY_NAME", lpServiceConfig->lpDisplayName,
"DEPENDENCIES", (lpServiceConfig->lpDependencies && lpServiceConfig->lpDependencies[0] == SC_GROUP_IDENTIFIERA) ?  "(GROUP) " : "", make_long_str(lpServiceConfig->lpDependencies),
"SERVICE_START_NAME", lpServiceConfig->lpServiceStartName
);
		//internal_printf("StartType: %s\nDisplayName: %s\nStartName: %s\nBinPath: %s\nLoadOrderGroup: %s\nError Mode: %s\n", EServiceStartup[lpServiceConfig->dwStartType], lpServiceConfig->lpDisplayName, lpServiceConfig->lpServiceStartName, lpServiceConfig->lpBinaryPathName, lpServiceConfig->lpLoadOrderGroup ? lpServiceConfig->lpLoadOrderGroup : "", EServiceError[lpServiceConfig->dwErrorControl]);
		
		dwResult = ERROR_SUCCESS;
	} while (0);

	if (lpServiceConfig)
	{
		intFree(lpServiceConfig);
	}

	return dwResult;
}

DWORD get_service_failure(SC_HANDLE scService)
{
	DWORD dwResult = ERROR_SUCCESS;
	LPSERVICE_FAILURE_ACTIONSA lpServiceConfig = NULL;
	DWORD cbBytesNeeded = 0;


	ADVAPI32$QueryServiceConfig2A(scService, SERVICE_CONFIG_FAILURE_ACTIONS, NULL, 0, &cbBytesNeeded);
	dwResult = KERNEL32$GetLastError();

	if (dwResult != ERROR_INSUFFICIENT_BUFFER)
	{
		goto end;
	}

	if ((lpServiceConfig = (LPSERVICE_FAILURE_ACTIONSA)intAlloc(cbBytesNeeded)) == NULL)
	{
		dwResult = ERROR_NOT_ENOUGH_MEMORY;
		goto end;
	}

	if (!ADVAPI32$QueryServiceConfig2A(scService, SERVICE_CONFIG_FAILURE_ACTIONS, (LPBYTE)lpServiceConfig, cbBytesNeeded, &cbBytesNeeded))
	{
		dwResult = KERNEL32$GetLastError();
		goto end;
	}

	internal_printf("\
\t%-30s : %lu\n\
\t%-30s : %s\n\
\t%-30s : %s\n",
"RESET_PERIOD (in seconds)", lpServiceConfig->dwResetPeriod,
"REBOOT_MESSAGE", (lpServiceConfig->lpRebootMsg) ? lpServiceConfig->lpRebootMsg : "",
"COMMAND_LINE", (lpServiceConfig->lpCommand) ? lpServiceConfig->lpCommand : ""
);
	for(DWORD x = 0; x < lpServiceConfig->cActions; x++)
	{
		internal_printf("\t%-30s : %s -- Delay = %lu milliseconds\n", "FAILURE_ACTIONS", resolveAction(lpServiceConfig->lpsaActions[x].Type), lpServiceConfig->lpsaActions[x].Delay);
	}
	dwResult = ERROR_SUCCESS;

	end:
	if (lpServiceConfig)
	{
		intFree(lpServiceConfig);
	}

	return dwResult;
}

DWORD get_service_triggers(SC_HANDLE scService)
{
	DWORD dwResult = ERROR_SUCCESS;
	PSERVICE_TRIGGER_INFO lpServiceConfig = NULL;
	DWORD cbBytesNeeded = 0;
	RPC_CSTR guid = NULL;


		ADVAPI32$QueryServiceConfig2A(scService, SERVICE_CONFIG_TRIGGER_INFO,  NULL, 0, &cbBytesNeeded);
		dwResult = KERNEL32$GetLastError();

		if (dwResult != ERROR_INSUFFICIENT_BUFFER)
		{
            goto end;
		}

		if ((lpServiceConfig = (PSERVICE_TRIGGER_INFO)intAlloc(cbBytesNeeded)) == NULL)
		{
            dwResult = ERROR_NOT_ENOUGH_MEMORY;
			goto end;
		}

		if (!ADVAPI32$QueryServiceConfig2A(scService, SERVICE_CONFIG_TRIGGER_INFO, (LPBYTE) lpServiceConfig, cbBytesNeeded, &cbBytesNeeded))
		{
			dwResult = KERNEL32$GetLastError();
            goto end;
		}
		if(lpServiceConfig->cTriggers == 0)
		{
			internal_printf("The service has not registered for any start or stop triggers.\n");
			dwResult = ERROR_SUCCESS;
			goto end;
		}

		for(DWORD x = 0; x < lpServiceConfig->cTriggers; x++)
		{
			if(RPCRT4$UuidToStringA(lpServiceConfig->pTriggers[x].pTriggerSubtype, &guid) != RPC_S_OK)
			{
				guid = NULL;
			}
			internal_printf("\t%s\n", (lpServiceConfig->pTriggers[x].dwAction > 0 && lpServiceConfig->pTriggers[x].dwAction < 3) ? Estartstop[lpServiceConfig->pTriggers[x].dwAction] : "(FAILED TO RESOLVE)");
			internal_printf("\t  %-20s : %s\n", 
			(lpServiceConfig->pTriggers[x].dwTriggerType < 21 && lpServiceConfig->pTriggers[x].dwTriggerType > 0) ? ETriggerType[lpServiceConfig->pTriggers[x].dwTriggerType] : "(FAILED TO RESOLVE)",
			(guid) ? (char *)guid : "(FAILED)");
			if(guid) {RPCRT4$RpcStringFreeA(&guid); guid = NULL;} 
			if( (lpServiceConfig->pTriggers[x].dwTriggerType == 20 || lpServiceConfig->pTriggers[x].dwTriggerType == 1 || lpServiceConfig->pTriggers[x].dwTriggerType == 4\
				|| lpServiceConfig->pTriggers[x].dwTriggerType == 6) && lpServiceConfig->pTriggers[x].cDataItems)
				{
					internal_printf("Has trigger specific data items but currently this is unsupported\n");
				}
			internal_printf("\n");
		}
		
		dwResult = ERROR_SUCCESS;

	end:
	if (lpServiceConfig)
	{
		intFree(lpServiceConfig);
	}

	return dwResult;
}

void query_service(LPCSTR cpServiceName)
{
	DWORD dwResult = ERROR_SUCCESS;
	SC_HANDLE scService = NULL;
	do
	{

		if ((scService = ADVAPI32$OpenServiceA(gscManager, cpServiceName, GENERIC_READ)) == NULL)
		{
			dwResult = KERNEL32$GetLastError();
			internal_printf("Unable to query any additional service information: %lu\n", dwResult);
			break;
		}
		if((dwResult = get_service_config(scService)) != 0)
		{
			internal_printf("\tUnable to query base configuration: %lu\n", dwResult);
		}
		if((dwResult = get_service_failure(scService)) != 0)
		{
			internal_printf("\tUnable to query failure configuration: %lu\n", dwResult);
		}
		if((dwResult = get_service_triggers(scService)) != 0)
		{
			internal_printf("\tUnable to query trigger configuration: %lu\n", dwResult);
		}
		internal_printf("\n");
	} while (0);

	if (scService)
	{
		ADVAPI32$CloseServiceHandle(scService);
	}
}

DWORD enumerate_services()
{
	DWORD dwResult = ERROR_SUCCESS;
	ENUM_SERVICE_STATUS_PROCESSA* pSsInfo = NULL; // set by EnumServicesStatusEX which scanbuild doesn't catch
	DWORD dwBytesNeeded = 0;
	DWORD dwServicesReturned = 0;
	DWORD dwResumeHandle = 0;
	DWORD dwServiceIndex = 0;
	BOOL bResult = FALSE;

	do
	{

		bResult = ADVAPI32$EnumServicesStatusExA(gscManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0,
			&dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL);

		if (!bResult && dwBytesNeeded)
		{
			pSsInfo = (ENUM_SERVICE_STATUS_PROCESSA*)intAlloc(dwBytesNeeded);

			if (!pSsInfo)
			{
                break;
			}

			bResult = ADVAPI32$EnumServicesStatusExA(gscManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)pSsInfo, dwBytesNeeded,
				&dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL);
			if (!bResult)
			{
				dwResult = KERNEL32$GetLastError();
				break;
			}
		}
		else
		{
			dwResult = KERNEL32$GetLastError();
			break;
		}


		for (dwServiceIndex = 0; dwServiceIndex < dwServicesReturned; ++dwServiceIndex)
		{
			internal_printf("\
SERVICE_NAME: %s\n\
DISPLAY_NAME: %s\n\
\t%-30s : %ld %s\n\
\t%-30s : %ld %s\n\
\t%-30s : %ld\n\
\t%-30s : %ld\n\
\t%-30s : %ld\n\
\t%-30s : %ld\n\
\t%-30s : %ld\n\
\t%-30s : %ld\n",
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
			query_service(pSsInfo[dwServiceIndex].lpServiceName);
				
		}

	} while (0);

	if (pSsInfo)
	{
		intFree(pSsInfo);
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
	DWORD result = ERROR_SUCCESS;
	datap parser;
	init_enums();
	BeaconDataParse(&parser, Buffer, Length);
	hostname = BeaconDataExtract(&parser, NULL);
	// Connect to service manager, don't want to have this above if we're doing remote

	if(!bofstart())
	{
		return;
	}
	if ((gscManager = ADVAPI32$OpenSCManagerA(hostname, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | GENERIC_READ)) == NULL)
	{
		result = KERNEL32$GetLastError();
	}
	if(ERROR_SUCCESS == result)
	{
		result = enumerate_services();
		if(ERROR_SUCCESS != result)
		{
			BeaconPrintf(CALLBACK_ERROR, "Failed to query service: %lu", result);
		}
	} else
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to connect to service manager: %lu", result);
	}
	
	printoutput(TRUE);
	cleanup_enums();

};

#else

int main()
{
	DWORD result = ERROR_SUCCESS;
	

	// Test #1
	init_enums();
	if ((gscManager = ADVAPI32$OpenSCManagerA("", SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | GENERIC_READ)) == NULL)
	{
		result = KERNEL32$GetLastError();
	}
	if (ERROR_SUCCESS == result)
	{
		result = enumerate_services();
		if (ERROR_SUCCESS != result)
		{
			BeaconPrintf(CALLBACK_ERROR, "Failed to query service: %lu", result);
		}
	}
	else
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to connect to service manager: %lu", result);
	}
	cleanup_enums();


	// Test #2
	init_enums();
	if ((gscManager = ADVAPI32$OpenSCManagerA("172.31.0.1", SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | GENERIC_READ)) == NULL)
	{
		result = KERNEL32$GetLastError();
	}
	if (ERROR_SUCCESS == result)
	{
		result = enumerate_services();
		if (ERROR_SUCCESS != result)
		{
			BeaconPrintf(CALLBACK_ERROR, "Failed to query service: %lu", result);
		}
	}
	else
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to connect to service manager: %lu", result);
	}
	cleanup_enums();


	// Test #3
	init_enums();
	if ((gscManager = ADVAPI32$OpenSCManagerA("asdf", SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT | GENERIC_READ)) == NULL)
	{
		result = KERNEL32$GetLastError();
	}
	if (ERROR_SUCCESS == result)
	{
		result = enumerate_services();
		if (ERROR_SUCCESS != result)
		{
			BeaconPrintf(CALLBACK_ERROR, "Failed to query service: %lu", result);
		}
	}
	else
	{
		BeaconPrintf(CALLBACK_ERROR, "Failed to connect to service manager: %lu", result);
	}
	cleanup_enums();


	return 0;
}

#endif
