#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "adcs_com.c"


HRESULT adcs_enum(
	LPWSTR pwszServer,
	LPWSTR pwszNameSpace,	
	LPWSTR pwszQuery
)
{
	HRESULT	hr						= S_OK;
	ADCS    m_ADCS;
	size_t	ullColumnsSize			= 0;
	LPWSTR	lpwszColumns			= NULL;	
	BSTR**	ppbstrResults			= NULL;
	DWORD	dwRowCount				= 0;
	DWORD	dwColumnCount			= 0;
	DWORD	dwCurrentRowIndex		= 0;
	DWORD	dwCurrentColumnIndex	= 0;

	// Initialize COM
	hr = adcs_com_Initialize(&m_ADCS);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_com_Initialize failed: 0x%08lx", hr);
		goto fail;
	}

	// Connect to ADCS on host
	hr = adcs_com_Connect(&m_ADCS, pwszServer, pwszNameSpace);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_com_Connect failed: 0x%08lx", hr);
		goto fail;
	}

	// Run the ADCS query
	hr = adcs_com_Query(&m_ADCS, pwszQuery);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_com_Query failed: 0x%08lx", hr);
		goto fail;
	}

	// Parse the results
	hr = adcs_com_ParseAllResults(&m_ADCS, &ppbstrResults, &dwRowCount, &dwColumnCount);
	if (FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_com_ParseAllResults failed: 0x%08lx", hr);
		goto fail;
	}

	// Display the resuls in CSV format
	for (dwCurrentRowIndex = 0; dwCurrentRowIndex < dwRowCount; dwCurrentRowIndex++)
	{
		for (dwCurrentColumnIndex = 0; dwCurrentColumnIndex < dwColumnCount; dwCurrentColumnIndex++)
		{
            if ( 0 == dwCurrentColumnIndex )		
            {
    			internal_printf( "%S", ppbstrResults[dwCurrentRowIndex][dwCurrentColumnIndex] );			
            }
            else
            {
                internal_printf( ", %S", ppbstrResults[dwCurrentRowIndex][dwCurrentColumnIndex] );    			
            }
		}
		internal_printf( "\n" );
	}

	hr = S_OK;

fail:

	for (dwCurrentRowIndex = 0; dwCurrentRowIndex < dwRowCount; dwCurrentRowIndex++)
	{
		for (dwCurrentColumnIndex = 0; dwCurrentColumnIndex < dwColumnCount; dwCurrentColumnIndex++)
		{
			SAFE_FREE(ppbstrResults[dwCurrentRowIndex][dwCurrentColumnIndex]);
		}
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ppbstrResults[dwCurrentRowIndex]);
	}
	
	if (ppbstrResults)
	{
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ppbstrResults);
		ppbstrResults = NULL;
	}

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
    pwszServer = (wchar_t *)BeaconDataExtract(&parser, NULL);
	pwszNameSpace = (wchar_t *)BeaconDataExtract(&parser, NULL);	
	pwszQuery = (wchar_t *)BeaconDataExtract(&parser, NULL);
	
	hr = adcs_enum(pwszServer, pwszNameSpace, pwszQuery);

	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_enum failed: 0x%08lx", hr);
	}

	printoutput(TRUE);
};
#else
int main(int argc, char ** argv)
{
	HRESULT hr = S_OK;

	hr = adcs_enum(L".", L"root\\cimv2", L"select * from win32_process");

	if (S_OK != hr)
	{
		BeaconPrintf(CALLBACK_ERROR, "adcs_enum failed: 0x%08lx", hr);
	}
	return 0;
}
#endif

	




