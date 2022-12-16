#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <lm.h>

void netuptime( wchar_t *servername)
{
	PSTAT_WORKSTATION_0 output = NULL;
	NET_API_STATUS stat = 0;
	wchar_t * service = L"LanmanWorkstation";

	//System allocated data automatically, we free it later with NetApiBufferFree Must free even on fail
	stat = NETAPI32$NetStatisticsGet(servername, service, 0, 0, (LPBYTE *) &output);
	if(stat == ERROR_SUCCESS)
	{

		// MSDN recommends converting SysTime->FileTime before doing arithmetic
		SYSTEMTIME curTime = {0};
		FILETIME curFTime = {0};
		LARGE_INTEGER utime;
		utime = output->StatisticsStartTime;
		KERNEL32$GetLocalTime(&curTime);

		memcpy(&curFTime, &utime, sizeof(utime));
		KERNEL32$FileTimeToSystemTime(&curFTime, &curTime);
		internal_printf("ServerName:   %S\n", servername);
		internal_printf("Boot time:    %4d-%.2d-%.2d %.2d:%.2d:%.2d\n", curTime.wYear, curTime.wMonth, 
				curTime.wDay, curTime.wHour, curTime.wMinute, curTime.wSecond);
	}
	else
	{
		internal_printf("Unable to retrieve up time remotly: %ld\n", stat);
	}
	
	NETAPI32$NetApiBufferFree(output);
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

	netuptime(servername);

	printoutput(TRUE);
};

#else

int main()
{
	netuptime(NULL);
	netuptime(L"172.31.0.1");
	return 0;
}

#endif