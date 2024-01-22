#include <windows.h>
#include "bofdefs.h"
#include "base.c"


void Reg_EnumKey(const char * hostname){
    
    DWORD i = 0, j = 0, retCode = 0;
	DWORD dwresult = 0;
	HKEY rootkey = 0;
	HKEY RemoteKey = 0;
    int sessionCount = 0;
    wchar_t whostname[256] = {0};
    DWORD whostname_len = 256;


	if(hostname == NULL)
	{
        internal_printf("[*] Querying local registry...\n");
		dwresult = ADVAPI32$RegOpenKeyExA(HKEY_USERS, NULL, 0, KEY_READ, &rootkey);

		if(dwresult){ goto END;}

        // get Fqdn name for localhost
		KERNEL32$GetComputerNameExW(ComputerNameDnsFullyQualified, (LPWSTR)&whostname, &whostname_len);
	}
	else
	{
        internal_printf("[*] Querying registry on %s...\n", hostname);
		dwresult = ADVAPI32$RegConnectRegistryA(hostname, HKEY_USERS, &RemoteKey);

		if(dwresult){
			internal_printf("failed to connect"); 
			goto END;
			}
		dwresult = ADVAPI32$RegOpenKeyExA(RemoteKey, NULL, 0, KEY_READ, &rootkey);

		if(dwresult){
			internal_printf("failed to open remote key"); 
			goto END;
			}
	}

    DWORD index = 0;
    CHAR subkeyName[256];
    DWORD subkeyNameSize = sizeof(subkeyName);

    while ((dwresult = ADVAPI32$RegEnumKeyExA(rootkey, index, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL)) == ERROR_SUCCESS) {
        BOOL isSID = TRUE;
        // if the subkey starts with S-1-5-21 and does not have an underscore, print
        if (subkeyName[0] == 'S' && subkeyName[1] == '-' && subkeyName[2] == '1' && subkeyName[3] == '-' && subkeyName[4] == '5' && subkeyName[5] == '-' && subkeyName[6] == '2' && subkeyName[7] == '1') {
            // if the subkey has an underscore anywhere in the string, skip
            for (j = 0; j < subkeyNameSize; j++) {
                if (subkeyName[j] == '_') {
                    isSID = FALSE;
                    break;
                }
            }
            if (isSID) {
                sessionCount++;
                internal_printf("-----------Registry Session---------\n");
                internal_printf("UserSid: %s\n", subkeyName);
                if (hostname == NULL) {
                    internal_printf("Host: %S\n", whostname);
                }
                else
                {
                    internal_printf("Host: %s\n", hostname);
                }
                internal_printf("---------End Registry Session-------\n\n");
            }
        }

        // Move to the next subkey
        index++;
        subkeyNameSize = sizeof(subkeyName);
    }

    internal_printf("[*] Found %d sessions in the registry\n", sessionCount);

    if (dwresult != ERROR_NO_MORE_ITEMS) {
        goto END;
    }



	END:
	if(rootkey){
    	ADVAPI32$RegCloseKey(rootkey);
	}

	if(RemoteKey)
		ADVAPI32$RegCloseKey(RemoteKey);
    
	return;
}

#ifdef BOF

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap parser = {0};
	const char * hostname = NULL;

	DWORD dwresult = 0;
    
	BeaconDataParse(&parser, Buffer, Length);
	hostname = BeaconDataExtract(&parser, NULL);
	
	
	//correct hostname param
	if(*hostname == 0)
	{
		hostname = NULL;
	}
	
	if(!bofstart())
	{
		return;
	}

	Reg_EnumKey(hostname);
	printoutput(TRUE);
};

#else

int main()
{
    Reg_EnumKey(NULL);
    Reg_EnumKey("Oxenfurt");
    Reg_EnumKey("192.168.0.215");
    return 0;
}

#endif