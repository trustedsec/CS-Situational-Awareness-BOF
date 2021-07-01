#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "adcs_com.c"


HRESULT adcs_enum()
{
	HRESULT	hr = S_OK;
	ADCS    m_ADCS;

	MSVCRT$memset(&m_ADCS, 0, sizeof(ADCS));

	// Initialize COM
	//internal_printf("adcs_com_Initialize\n");
	hr = adcs_com_Initialize(&m_ADCS);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_com_Initialize failed: 0x%08lx\n", hr);
		goto fail;
	}

	// Connect to ADCS on host
	//internal_printf("adcs_com_Connect\n");
	hr = adcs_com_Connect(&m_ADCS);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_com_Connect failed: 0x%08lx\n", hr);
		goto fail;
	}

	// Run the ADCS enumeration to get info for all CAs
	//internal_printf("adcs_com_GetCertificateServices\n");
	hr = adcs_com_GetCertificateServices(&m_ADCS);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_com_GetCertificateServices failed: 0x%08lx\n", hr);
		goto fail;
	}

	// Print the results
	//internal_printf("adcs_com_PrintInfo\n");
	hr = adcs_com_PrintInfo(&m_ADCS);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_com_PrintInfo failed: 0x%08lx\n", hr);
		goto fail;
	}

	hr = S_OK;

fail:

	// Perform the clean up
	//internal_printf("adcs_com_Finalize\n");
	adcs_com_Finalize(&m_ADCS);
	
	return hr;
}

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
	
	hr = adcs_enum();

	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_enum failed: 0x%08lx\n", hr);
	}

	printoutput(TRUE);
};
#else
int main(int argc, char ** argv)
{
	HRESULT hr = S_OK;

	hr = adcs_enum();

	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_enum failed: 0x%08lx\n", hr);
	}
	return 0;
}
#endif

	




