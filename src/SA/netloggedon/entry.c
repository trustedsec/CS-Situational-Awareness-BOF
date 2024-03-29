#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <lm.h>

void getnetloggedon( wchar_t *servername)
{
	PWKSTA_USER_INFO_1 output = NULL, current = NULL;
	DWORD entries = 0, pos = 0, totalentrieshint = 0; 
	DWORD resume = 0;
	NET_API_STATUS stat = 0;
	//System allocated data automatically, we free it later with NetApiBufferFree Must free even on fail
   internal_printf("Users logged on: \n");
   internal_printf("---------------------%S----------------------------------\n", servername == NULL ? L"(Local)" : servername);

	do{
		stat = NETAPI32$NetWkstaUserEnum(servername, 1, (LPBYTE *) &output, MAX_PREFERRED_LENGTH, &entries, &totalentrieshint, &resume);
		if(stat == ERROR_SUCCESS || stat == ERROR_MORE_DATA)
		{
			current = output;
			for(pos = 0; pos < entries; pos++)
			{
				
				internal_printf("\nUsername: %S\n", current->wkui1_username);
				internal_printf("Domain:       %S\n", current->wkui1_logon_domain);
				internal_printf("Oth_domains:  %S\n", current->wkui1_oth_domains);
				internal_printf("Logon server: %S\n", current->wkui1_logon_server);
				
				current++;
			}
		}
		else
		{
			internal_printf("Unable to list logged on users : %ld\n", stat);
		}
		
		NETAPI32$NetApiBufferFree(output);
	}while(stat == ERROR_MORE_DATA);

}

#ifdef BOF

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap parser = {0};
	BeaconDataParse(&parser, Buffer, Length);

	wchar_t * servername = ( wchar_t *)BeaconDataExtract(&parser, NULL);

	if(*servername == 0)
	{
		servername = NULL;
	}
	if(!bofstart())
	{
		return;
	}

	getnetloggedon(servername);

	printoutput(TRUE);
};

#else

int main()
{
	getnetloggedon(NULL);
	getnetloggedon(L"172.31.0.1");
	return 0;
}

#endif