#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <lm.h>

void listSharesAdmin( wchar_t *servername)
{
	PSHARE_INFO_2 output = NULL, current = NULL;
	DWORD entries = 0, pos = 0, totalentrieshint = 0; 
	DWORD resume = 0;
	NET_API_STATUS stat = 0;
	//System allocated data automatically, we free it later with NetApiBufferFree Must free even on fail
   internal_printf("Share:              Local Path:                   Uses:   Descriptor:\n");
   internal_printf("---------------------%S----------------------------------\n", servername == NULL ? L"(Local)" : servername);

	do{
		stat = NETAPI32$NetShareEnum(servername, 2, (LPBYTE *) &output, MAX_PREFERRED_LENGTH, &entries, &totalentrieshint, &resume);
		if(stat == ERROR_SUCCESS || stat == ERROR_MORE_DATA)
		{
			current = output;
			for(pos = 0; pos < entries; pos++)
			{
				internal_printf("%-20S%-30S%-8lu %S\n",current->shi2_netname,current->shi2_path, current->shi2_current_uses, current->shi2_remark);
				current++;
			}
		}
		else
		{
			internal_printf("Unable to list share : %ld\n", stat);
		}
		
		NETAPI32$NetApiBufferFree(output);
	}while(stat == ERROR_MORE_DATA);

}


void listSharesUser( wchar_t *servername)
{
	PSHARE_INFO_0 output = NULL, current = NULL;
	DWORD entries = 0, pos = 0, totalentrieshint = 0; 
	DWORD resume = 0;
	NET_API_STATUS stat = 0;
	//System allocated data automatically, we free it later with NetApiBufferFree Must free even on fail
   internal_printf("Share: \n");
   internal_printf("---------------------%S----------------------------------\n", servername == NULL ? L"(Local)" : servername);

	do{
		stat = NETAPI32$NetShareEnum(servername, 0, (LPBYTE *) &output, MAX_PREFERRED_LENGTH, &entries, &totalentrieshint, &resume);
		if(stat == ERROR_SUCCESS || stat == ERROR_MORE_DATA)
		{
			current = output;
			for(pos = 0; pos < entries; pos++)
			{
				internal_printf("%S\n",current->shi0_netname);
				current++;
			}
		}
		else
		{
			internal_printf("Unable to list share : %ld\n", stat);
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
	int asAdmin = 0;
	BeaconDataParse(&parser, Buffer, Length);

	wchar_t * sharename = ( wchar_t *)BeaconDataExtract(&parser, NULL);
	asAdmin = BeaconDataInt(&parser);
	if(*sharename == 0)
	{
		sharename = NULL;
	}
	if(!bofstart())
	{
		return;
	}
	if(asAdmin)
	{
		listSharesAdmin(sharename);
	}
	else
	{
		listSharesUser(sharename);
	}
	
	printoutput(TRUE);
};

#else

int main()
{
	listSharesAdmin(NULL);
	listSharesUser(NULL);
	listSharesAdmin(L"172.31.0.1");
	listSharesUser(L"172.31.0.1");
	return 0;
}

#endif