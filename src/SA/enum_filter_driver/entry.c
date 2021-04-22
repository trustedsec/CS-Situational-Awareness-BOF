#include <windows.h>
#include <process.h>
#include "bofdefs.h"
#include "base.c"

#define SZ_SERVICE_KEY "SYSTEM\\CurrentControlSet\\Services"
#define SZ_INSTANCE_KEY "Instances"
#define SZ_ALTITUDE_VALUE "Altitude"


DWORD Enum_Filter_Driver(LPCSTR szHostName)
{
    DWORD dwErrorCode = 0;
    HKEY hRootKey = NULL;
    HKEY hRemoteKey = NULL;
    HKEY hServiceKey = NULL;
    HKEY hInstanceKey = NULL;
    HKEY hInstanceSubkey = NULL;

    LPSTR szServiceKeyName = NULL;
    DWORD dwServiceKeyNameCount = MAX_PATH;
    DWORD dwServiceKeyIndex = 0;
    LPSTR szInstancesSubkeyName = NULL;
    DWORD dwInstancesSubkeyNameCount = MAX_PATH;
    DWORD dwInstancesSubkeyIndex = 0;
    LPSTR szAltitudeValue = NULL;
    DWORD dwAltitudeValue = 0;
    DWORD dwAltitudeValueType = 0;
    DWORD dwAltitudeValueCount = MAX_PATH;

    // allocate buffers
    szServiceKeyName = (LPSTR)intAlloc(MAX_PATH);
    if ( NULL == szServiceKeyName ) { internal_printf("intAlloc FAILED (%lu)", dwErrorCode); goto END; }
    intZeroMemory(szServiceKeyName, MAX_PATH);
    szInstancesSubkeyName = (LPSTR)intAlloc(MAX_PATH);
    if ( NULL == szInstancesSubkeyName ) { internal_printf("intAlloc FAILED (%lu)", dwErrorCode); goto END; }
    intZeroMemory(szInstancesSubkeyName, MAX_PATH);
    szAltitudeValue = (LPSTR)intAlloc(MAX_PATH);
    if ( NULL == szAltitudeValue ) { internal_printf("intAlloc FAILED (%lu)", dwErrorCode); goto END; }
    intZeroMemory(szAltitudeValue, MAX_PATH);

	// open root key
    if ( NULL == szHostName )
	{
		dwErrorCode = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, SZ_SERVICE_KEY, 0, KEY_READ, &hRootKey);
		if ( ERROR_SUCCESS != dwErrorCode ) { internal_printf("RegOpenKeyExA FAILED (%lu)", dwErrorCode); goto END; }
	}
	else
	{
		dwErrorCode = ADVAPI32$RegConnectRegistryA(szHostName, HKEY_LOCAL_MACHINE, &hRemoteKey);
        if ( ERROR_SUCCESS != dwErrorCode ) { internal_printf("RegConnectRegistryA FAILED (%lu)", dwErrorCode); goto END; }

		dwErrorCode = ADVAPI32$RegOpenKeyExA(hRemoteKey, SZ_SERVICE_KEY, 0, KEY_READ, &hRootKey);
        if ( ERROR_SUCCESS != dwErrorCode ) { internal_printf("RegOpenKeyExA FAILED (%lu)", dwErrorCode); goto END; }
	}
    
    // loop through all service subkeys
    dwServiceKeyIndex = 0;
    dwErrorCode = ADVAPI32$RegEnumKeyExA(hRootKey, dwServiceKeyIndex, szServiceKeyName, &dwServiceKeyNameCount, NULL, NULL, NULL, NULL);
    while ( dwErrorCode != ERROR_NO_MORE_ITEMS )
    {
        //internal_printf("loop through all service subkeys: %lu\n", dwServiceKeyIndex);

        // open service subkey
        dwErrorCode = ADVAPI32$RegOpenKeyExA(hRootKey, szServiceKeyName, 0, KEY_READ, &hServiceKey);
        if ( ERROR_SUCCESS == dwErrorCode )
        {
            //internal_printf("open service subkey: %s\n", szServiceKeyName);

            // open service subkey's Instances subkey
            dwErrorCode = ADVAPI32$RegOpenKeyExA(hServiceKey, SZ_INSTANCE_KEY, 0, KEY_READ, &hInstanceKey);
            if ( ERROR_SUCCESS == dwErrorCode ) 
            {
                //internal_printf("open service subkey's Instances subkey\n");

                // loop through all instances subkeys
                dwInstancesSubkeyIndex = 0;
                dwErrorCode = ADVAPI32$RegEnumKeyExA(hInstanceKey, dwInstancesSubkeyIndex, szInstancesSubkeyName, &dwInstancesSubkeyNameCount, NULL, NULL, NULL, NULL);
                while ( dwErrorCode != ERROR_NO_MORE_ITEMS )
                {
                    //internal_printf("loop through all instances subkeys: %lu\n", dwInstancesSubkeyIndex);

                    // open instances subkey
                    dwErrorCode = ADVAPI32$RegOpenKeyExA(hInstanceKey, szInstancesSubkeyName, 0, KEY_READ, &hInstanceSubkey);
                    if ( ERROR_SUCCESS == dwErrorCode )
                    {
                        //internal_printf("open instances subkey: %s\n", szInstancesSubkeyName);

                        // query for altitude value
                        dwErrorCode = ADVAPI32$RegQueryValueExA(hInstanceSubkey, SZ_ALTITUDE_VALUE, NULL, &dwAltitudeValueType, szAltitudeValue, &dwAltitudeValueCount);
                        if ( ERROR_SUCCESS == dwErrorCode )
                        {
                            dwAltitudeValue = MSVCRT$strtoul(szAltitudeValue, NULL, 10);

                            //internal_printf("dwAltitudeValue:  %lu\n", dwAltitudeValue);

                            if ( (dwAltitudeValue >= 360000) && (dwAltitudeValue <= 389999) )
                            {
                                internal_printf("activitymonitor,%s,%lu\n", szServiceKeyName, dwAltitudeValue);
                            }
                            else if ( (dwAltitudeValue >= 320000) && (dwAltitudeValue <= 329999) )
                            {
                                internal_printf("antivirus,%s,%lu\n", szServiceKeyName, dwAltitudeValue);
                            }
                            else if ( (dwAltitudeValue >= 260000) && (dwAltitudeValue <= 269999) )
                            {
                                internal_printf("contentscreener,%s,%lu\n", szServiceKeyName, dwAltitudeValue);
                            }
                            
                        } // end else query for altitude value was successful
                        else
                        {
                            internal_printf("RegQueryValueExA FAILED (%lu)", dwErrorCode);
                        } // end else query for altitude value failed

                        intZeroMemory(szAltitudeValue, MAX_PATH);
                        dwAltitudeValueCount = MAX_PATH;
                        
                    } // end if open instances subkey was successful
                    else
                    {
                        internal_printf("RegOpenKeyExA FAILED (%lu)", dwErrorCode);
                    } // end else open instances subkey failed

                    if ( hInstanceSubkey ) { ADVAPI32$RegCloseKey(hInstanceSubkey); hInstanceSubkey = NULL; }

                    intZeroMemory(szInstancesSubkeyName, MAX_PATH);
                    dwInstancesSubkeyNameCount = MAX_PATH;

                    dwInstancesSubkeyIndex++;
                    dwErrorCode = ADVAPI32$RegEnumKeyExA(hInstanceKey, dwInstancesSubkeyIndex, szInstancesSubkeyName, &dwInstancesSubkeyNameCount, NULL, NULL, NULL, NULL);
                } // end loop through all instances subkeys

                if ( hInstanceSubkey ) { ADVAPI32$RegCloseKey(hInstanceSubkey); hInstanceSubkey = NULL; }
                
            } // end if open service subkey's Instances subkey was successful

            if ( hInstanceKey ) { ADVAPI32$RegCloseKey(hInstanceKey); hInstanceKey = NULL; }

        } // end if open service subkey was successful
        else
        {
            internal_printf("RegOpenKeyExA FAILED (%lu)", dwErrorCode);
        } // end else open service subkey failed

        if ( hServiceKey ) { ADVAPI32$RegCloseKey(hServiceKey); hServiceKey = NULL; }

        intZeroMemory(szServiceKeyName, MAX_PATH);
        dwServiceKeyNameCount = MAX_PATH;

        dwServiceKeyIndex++;
        dwErrorCode = ADVAPI32$RegEnumKeyExA(hRootKey, dwServiceKeyIndex, szServiceKeyName, &dwServiceKeyNameCount, NULL, NULL, NULL, NULL);
    } // end loop through all service subkeys

    if ( dwErrorCode == ERROR_NO_MORE_ITEMS ) { dwErrorCode = ERROR_SUCCESS; }

END:

    if ( szAltitudeValue ) { intFree(szAltitudeValue); szAltitudeValue = NULL; }

    if ( szInstancesSubkeyName ) { intFree(szInstancesSubkeyName); szInstancesSubkeyName = NULL; }

    if ( szServiceKeyName ) { intFree(szServiceKeyName); szServiceKeyName = NULL; }

    if ( hInstanceSubkey ) { ADVAPI32$RegCloseKey(hInstanceSubkey); hInstanceSubkey = NULL; }

    if ( hInstanceKey ) { ADVAPI32$RegCloseKey(hInstanceKey); hInstanceKey = NULL; }

    if ( hServiceKey ) { ADVAPI32$RegCloseKey(hServiceKey); hServiceKey = NULL; }

    if ( hRootKey ) { ADVAPI32$RegCloseKey(hRootKey); hRootKey = NULL; }

	if ( hRemoteKey ) { ADVAPI32$RegCloseKey(hRemoteKey); hRemoteKey = NULL; }

	return dwErrorCode;
}




#ifdef BOF
VOID go( IN PCHAR Buffer, IN ULONG Length ) 
{
    DWORD dwErrorCode = ERROR_SUCCESS;
	datap parser = {0};
	LPCSTR szHostName = NULL;

    // Get arguments
	BeaconDataParse(&parser, Buffer, Length);
	szHostName = (LPCSTR)BeaconDataExtract(&parser, NULL);

	// Check arguments
	if (*szHostName == 0)
	{
		szHostName = NULL;
	}
	
	if(!bofstart())
	{
		return;
	}
    
	dwErrorCode = Enum_Filter_Driver(szHostName);
	if (ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "Enum_Filter_Driver FAILED (%lu)\n", dwErrorCode);
        goto END;
	}

    internal_printf("SUCCESS.\n");

END:
	printoutput(TRUE);

	bofstop();
};
#else
int main()
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    LPCSTR szHostName = NULL;

    dwErrorCode = Enum_Filter_Driver(szHostName);
	if (ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "Enum_Filter_Driver FAILED (%lu)\n", dwErrorCode);
        goto END;
	}

    internal_printf("SUCCESS.\n");

END:

    return dwErrorCode;
}
#endif