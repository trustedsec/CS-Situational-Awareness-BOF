#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <lm.h>
#include <time.h>

void nettime(LPCWSTR pszServer)
{
	TIME_OF_DAY_INFO *pTod = NULL;
	NET_API_STATUS nStatus;
	
	nStatus = NETAPI32$NetRemoteTOD(pszServer, (LPBYTE *) &pTod);
	
	if (pszServer == NULL)
    {
        pszServer = L"localhost";
    }

	if (nStatus == NERR_Success)
	{
		time_t elapsed = pTod->tod_elapsedt;
		// Adjust the elapsed time with the timezone offset
		elapsed -= pTod->tod_timezone * 60;
		struct tm* ptm = MSVCRT$gmtime(&elapsed);

		if (ptm != NULL)
		{
			char date[80];
			MSVCRT$strftime(date, sizeof(date), "%m/%d/%Y %I:%M:%S %p", ptm);

			internal_printf("Local time (GMT%+03d:00) at %S is %s\n", -pTod->tod_timezone/60, pszServer, date);
		}
	} else {
		internal_printf("Unable to retrieve up time remotely: %ld\n", nStatus);
	}

	if(pTod)
		{NETAPI32$NetApiBufferFree(pTod);}
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

	nettime(servername);

	printoutput(TRUE);
};

#else

int main()
{
	nettime(NULL);
	nettime(L"\\\\heh heh");
	return 0;
}

#endif
