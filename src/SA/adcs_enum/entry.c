#include <windows.h>
#include <stdio.h>
#define DYNAMIC_LIB_COUNT 2
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "adcs_enum.c"


#ifdef BOF
VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	HRESULT hr = S_OK;
	datap parser;
	wchar_t * domain = NULL;
	int len;
    
	if (!bofstart())
	{
		return;
	}

	BeaconDataParse(&parser, Buffer, Length);
	
	domain = (wchar_t *)BeaconDataExtract(&parser, &len);

	hr = adcs_enum(domain);

	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_enum failed: 0x%08lx\n", hr);
	}
	else
	{
		internal_printf("\nadcs_enum SUCCESS.\n");
	}

	printoutput(TRUE);
};
#else
int main(int argc, char ** argv)
{
	HRESULT hr = S_OK;
	wchar_t domainarg[MAX_PATH];
	wchar_t* domain = NULL;

	if (argc==2)
	{
		memset(domainarg, 0, sizeof(wchar_t)*MAX_PATH);
		mbstowcs(domainarg, argv[1], MAX_PATH);
		domain = domainarg;
	}

	hr = adcs_enum(domain);

	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_enum failed: 0x%08lx\n", hr);
	}
	else
	{
		internal_printf("\nadcs_enum SUCCESS.\n");
	}

	return 0;
}
#endif

	




