#include <windows.h>
#include <stdio.h>
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
	wchar_t * pwszEnumerationType = NULL;
    
	if (!bofstart())
	{
		return;
	}

	BeaconDataParse(&parser, Buffer, Length);
	
	hr = adcs_enum();

	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_enum failed: 0x%08lx\n", hr);
	}

	internal_printf("SUCCESS\n");

	printoutput(TRUE);
};
#else
int main(int argc, char ** argv)
{
	HRESULT hr = S_OK;
	wchar_t * pwszEnumerationType = NULL;

	hr = adcs_enum();

	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_enum failed: 0x%08lx\n", hr);
	}

	internal_printf("SUCCESS\n");

	return 0;
}
#endif

	




