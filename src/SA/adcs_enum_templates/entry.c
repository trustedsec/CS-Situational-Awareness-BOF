#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "adcs_enum_templates.c"


#ifdef BOF
VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	HRESULT hr = S_OK;
	datap parser;
	wchar_t * pwszServer = NULL;
	wchar_t * pwszNameSpace = NULL;	
	wchar_t * pwszQuery = NULL;
    
	if (!bofstart())
	{
		return;
	}

	BeaconDataParse(&parser, Buffer, Length);
	
	hr = adcs_enum_templates();

	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_enum_templates failed: 0x%08lx\n", hr);
	}

	printoutput(TRUE);
};
#else
int main(int argc, char ** argv)
{
	HRESULT hr = S_OK;

	hr = adcs_enum_templates();

	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_enum_templates failed: 0x%08lx\n", hr);
	}
	return 0;
}
#endif

	




